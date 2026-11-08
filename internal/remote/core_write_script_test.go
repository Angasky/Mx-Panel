package remote

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCoreWriteScriptActualRollback(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		for _, scenario := range []string{"success", "validation", "restart", "inactive", "verify", "term", "rollback-failure", "conflict"} {
			t.Run(kind+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				write := func(name, body string) {
					t.Helper()
					p := filepath.Join(root, name)
					if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(body), 0700); err != nil {
						t.Fatal(err)
					}
				}
				old := `{"inbounds":[],"outbounds":[],"log":{"level":"warn"}}`
				write("config.json", old)
				write("lock", "")
				write("mock/core", `#!/bin/bash
set -eu
[ "$SCENARIO" != validation ]
`)
				write("mock/systemctl", `#!/bin/bash
set -eu
case "$1" in
 restart)
  count=0
  [ ! -f "$FIXTURE_ROOT/restarts" ] || count=$(cat "$FIXTURE_ROOT/restarts")
  count=$((count+1))
  echo "$count" > "$FIXTURE_ROOT/restarts"
  if [ "$SCENARIO" = rollback-failure ]; then exit 91; fi
  if [ "$count" = 1 ]; then
   if [ "$SCENARIO" = term ]; then kill -TERM "$PPID"; fi
   if [ "$SCENARIO" = restart ]; then exit 92; fi
  fi
  ;;
 is-active)
  if [ "$SCENARIO" = inactive ] && [ "$(cat "$FIXTURE_ROOT/restarts")" = 1 ]; then exit 93; fi
  ;;
 *) exit 99 ;;
esac
`)
				next := Record{"inbounds": []any{}, "outbounds": []any{}, "log": Record{"level": "debug"}}
				verify := ""
				if scenario == "verify" {
					verify = "false\n"
				}
				script, err := coreWriteScript(kind, []byte(old), next, "", verify)
				if err != nil {
					t.Fatal(err)
				}
				path, _ := corePath(kind)
				script = strings.NewReplacer(path, root+"/config.json", "/usr/local/bin/xray", root+"/mock/core", "/usr/bin/sing-box", root+"/mock/core", "/var/lock/mxioc-xui-install.lock", root+"/lock").Replace(script)
				if scenario == "conflict" {
					write("config.json", `{"changed":true}`)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, "bash", "-s")
				cmd.Stdin = strings.NewReader(script)
				cmd.Env = append(os.Environ(), "PATH="+root+"/mock:"+os.Getenv("PATH"), "FIXTURE_ROOT="+root, "SCENARIO="+scenario)
				out, err := cmd.CombinedOutput()
				raw, readErr := os.ReadFile(filepath.Join(root, "config.json"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				if scenario == "success" {
					if err != nil || !strings.Contains(string(out), "MXIOC_CORE_APPLIED") || string(raw) == old {
						t.Fatal("apply", string(out), err)
					}
				} else {
					if err == nil || strings.Contains(string(out), "MXIOC_CORE_APPLIED") {
						t.Fatal("failure reported success", string(out), err)
					}
					if scenario == "conflict" {
						if string(raw) != `{"changed":true}` {
							t.Fatal("concurrent edit overwritten")
						}
						return
					}
					if string(raw) != old {
						t.Fatal("old configuration not restored", string(out))
					}
					if scenario == "rollback-failure" {
						if !strings.Contains(string(out), "MXIOC_CORE_ROLLBACK_FAILED") {
							t.Fatal("rollback failure hidden", string(out))
						}
					} else if scenario != "validation" && !strings.Contains(string(out), "MXIOC_CORE_ROLLED_BACK") {
						t.Fatal("rollback unconfirmed", string(out))
					}
				}
				backups, _ := filepath.Glob(root + "/config.json.backup.*")
				if len(backups) != 1 {
					t.Fatal("recovery backup not retained", backups)
				}
				backup, _ := os.ReadFile(backups[0])
				if string(backup) != old {
					t.Fatal("backup damaged")
				}
				candidates, _ := filepath.Glob(root + "/config.json.mxioc.*")
				if len(candidates) != 0 {
					t.Fatal("candidate leaked")
				}
			})
		}
	}
}
