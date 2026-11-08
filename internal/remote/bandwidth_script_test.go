package remote

import (
	"context"
	"encoding/base64"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Executes the actual shell transaction. All paths and commands that could
// affect host networking or services are isolated, including canonicalization.
func TestBandwidthScriptFailureAndRetry(t *testing.T) {
	for _, scenario := range []string{"success", "check", "enable", "apply", "persist", "foreign", "existing-check", "existing-enable", "existing-apply", "existing-persist", "reboot-persist"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			write := func(name, body string) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{"mock", "tmp", "etc/systemd/system", "var/lock"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			write("mock/nft", `#!/bin/bash
set -eu
live="$FIXTURE_ROOT/live"
case "$*" in
 'list tables') if [ -f "$live" ]; then echo 'table inet mxioc_bandwidth'; fi ;;
 '-s list table inet mxioc_bandwidth') cat "$live" ;;
 '-c -f '*) [ "$SCENARIO" != check ] ;;
 '-f '*)
  [ "$SCENARIO" != apply ]
  sed '/^delete table inet mxioc_bandwidth$/d' "$2" > "$live"
  touch "$FIXTURE_ROOT/applied"
  ;;
 *) exit 99 ;;
esac
`)
			write("mock/unshare", `#!/bin/bash
set -eu
# Only canonicalization runs here. Never execute the supplied shell program.
for arg; do file="$arg"; done
cat "$file"
`)
			write("mock/systemctl", `#!/bin/bash
set -eu
case "$1" in
 daemon-reload) : ;;
 enable) [ "$SCENARIO" != enable ]; touch "$FIXTURE_ROOT/enabled" ;;
 *) exit 99 ;;
esac
`)
			write("mock/mv", `#!/bin/bash
set -eu
if [ "$SCENARIO" = persist ] && [ -f "$FIXTURE_ROOT/applied" ]; then exit 93; fi
exec /bin/mv "$@"
`)
			old, err := legacyBandwidthRules(Record{})
			if err != nil {
				t.Fatal(err)
			}
			next, err := legacyBandwidthRules(Record{"1": Record{"port": 24443, "protocols": []any{"tcp"}, "uploadKbps": 1000, "downloadKbps": 2000}})
			if err != nil {
				t.Fatal(err)
			}
			script := "set -Eeuo pipefail\nold=" + quote(base64.StdEncoding.EncodeToString([]byte(old))) + "\nnext=" + quote(base64.StdEncoding.EncodeToString([]byte(next))) + "\nfresh=1\n" + legacyBandwidthApply
			script = strings.NewReplacer("/etc/mxioc-bandwidth", root+"/etc/mxioc-bandwidth", "/etc/systemd/system", root+"/etc/systemd/system", "/var/lock", root+"/var/lock").Replace(script)
			if scenario == "foreign" {
				write("live", "foreign-rules\n")
			}
			run := func(mode string) (string, error) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "bash", "-s")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = append(os.Environ(), "PATH="+root+"/mock:"+os.Getenv("PATH"), "FIXTURE_ROOT="+root, "SCENARIO="+mode, "TMPDIR="+root+"/tmp")
				output, err := cmd.CombinedOutput()
				return string(output), err
			}
			existing := strings.HasPrefix(scenario, "existing-") || strings.HasPrefix(scenario, "reboot-")
			phase := strings.TrimPrefix(strings.TrimPrefix(scenario, "existing-"), "reboot-")
			if existing {
				output, err := run("success")
				if err != nil {
					t.Fatal("bootstrap", output, err)
				}
				old = next
				next, err = legacyBandwidthRules(Record{
					"1": Record{"port": 24443, "protocols": []any{"tcp"}, "uploadKbps": 2000, "downloadKbps": 3000},
					"2": Record{"port": 24444, "protocols": []any{"udp"}, "uploadKbps": 100, "downloadKbps": 100},
				})
				if err != nil {
					t.Fatal(err)
				}
				body := script[strings.Index(script, "\ncommand -v"):]
				script = "set -Eeuo pipefail\nold=" + quote(base64.StdEncoding.EncodeToString([]byte(old))) + "\nnext=" + quote(base64.StdEncoding.EncodeToString([]byte(next))) + "\nfresh=0\n" + body
			}
			output, err := run(phase)
			if scenario == "success" {
				if err != nil {
					t.Fatal(output, err)
				}
			} else if err == nil || strings.Contains(output, "MXIOC_LEGACY_BANDWIDTH_APPLIED") {
				t.Fatal("unconfirmed transaction reported success", output, err)
			}
			if scenario == "foreign" {
				raw, _ := os.ReadFile(filepath.Join(root, "live"))
				if string(raw) != "foreign-rules\n" {
					t.Fatal("foreign table overwritten")
				}
				return
			}
			if phase == "check" || phase == "enable" || phase == "apply" {
				if existing {
					raw, _ := os.ReadFile(filepath.Join(root, "live"))
					if string(raw) != old {
						t.Fatal("failed update changed old live rules")
					}
				} else if _, err := os.Stat(filepath.Join(root, "live")); !os.IsNotExist(err) {
					t.Fatal("failed pre-application changed live rules", err)
				}
			}
			if phase == "persist" {
				live, _ := os.ReadFile(filepath.Join(root, "live"))
				saved, _ := os.ReadFile(filepath.Join(root, "etc/mxioc-bandwidth/rules.nft"))
				if string(live) != next || string(saved) != old {
					t.Fatal("failure phase not reached")
				}
			}
			if strings.HasPrefix(scenario, "reboot-") {
				// Model the restore unit loading the last durable rules after restart.
				saved, err := os.ReadFile(filepath.Join(root, "etc/mxioc-bandwidth/rules.nft"))
				if err != nil {
					t.Fatal(err)
				}
				write("live", string(saved))
			}
			// The same transaction must converge after a lost response or phase failure.
			output, err = run("success")
			if err != nil || !strings.Contains(output, "MXIOC_LEGACY_BANDWIDTH_APPLIED") {
				t.Fatal("retry failed", output, err)
			}
			live, _ := os.ReadFile(filepath.Join(root, "live"))
			saved, _ := os.ReadFile(filepath.Join(root, "etc/mxioc-bandwidth/rules.nft"))
			if string(live) != next || string(saved) != next {
				t.Fatal("retry failed to persist confirmed live state")
			}
		})
	}
}
