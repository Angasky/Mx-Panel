package releaseupdate

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/deploy"
)

func TestPurgeScriptIsolated(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer requires root")
	}
	for _, scenario := range []string{"success", "legacy-active", "legacy-enabled", "data-symlink", "auth-symlink", "mounted", "inventory-failed", "delete-failed", "no-version"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "go")
			release := filepath.Join(base, "releases", "v1.0.0")
			data := filepath.Join(root, "data")
			auth := filepath.Join(root, "auth")
			unit := filepath.Join(root, "unit")
			bin := filepath.Join(root, "bin")
			for _, dir := range []string{release, data, bin} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			write := func(path, body string, mode os.FileMode) {
				t.Helper()
				if err := os.WriteFile(path, []byte(body), mode); err != nil {
					t.Fatal(err)
				}
			}
			write(unit, "unit", 0600)
			write(filepath.Join(release, "mxioc-go-release.service"), "unit", 0600)
			write(auth, "credentials", 0600)
			write(filepath.Join(data, "subscription.yaml"), "subscription", 0600)
			outside := filepath.Join(root, "outside")
			write(outside, "unrelated", 0600)
			if err := os.Symlink(outside, filepath.Join(data, "external-link")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(release, filepath.Join(base, "current")); err != nil {
				t.Fatal(err)
			}
			if scenario == "data-symlink" {
				if err := os.Rename(data, data+"-real"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(data+"-real", data); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "auth-symlink" {
				os.Rename(auth, auth+"-real")
				os.Symlink(auth+"-real", auth)
			}
			write(filepath.Join(bin, "systemctl"), `#!/bin/bash
set -eu
printf '%s\n' "$*" >> "$TEST_ROOT/calls"
case "$1" in
 is-active) [[ "$TEST_CASE" == legacy-active && "$3" == mxioc-rule-manager.service ]] ;;
 is-enabled) [[ "$TEST_CASE" == legacy-enabled && "$3" == mxioc-rule-manager.service ]] ;;
 *) exit 0 ;;
esac
`, 0700)
			write(filepath.Join(bin, "findmnt"), `#!/bin/bash
[[ "$TEST_CASE" != inventory-failed ]] || exit 1
if [[ "$TEST_CASE" == mounted ]]; then echo "$TEST_ROOT/data/nested"; else echo /; fi
`, 0700)
			write(filepath.Join(bin, "rm"), `#!/bin/bash
if [[ "$TEST_CASE" == delete-failed && "$*" == "-rf --one-file-system -- $TEST_ROOT/data" ]]; then exit 1; fi
exec /bin/rm "$@"
`, 0700)
			script := strings.NewReplacer("base=/opt/mxioc-go", "base="+base, "data=/opt/mxioc-rule-manager", "data="+data, "auth=/etc/mxioc-rule-manager.auth.json", "auth="+auth, "unit=/etc/systemd/system/mxioc-go.service", "unit="+unit, "/run/lock/mxioc-go-release.lock", filepath.Join(root, "lock")).Replace(deploy.Installer)
			path := filepath.Join(root, "installer.sh")
			write(path, script, 0600)
			command := exec.Command("bash", path, "uninstall")
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_ROOT="+root, "TEST_CASE="+scenario, "MXIOC_GO_PURGE_DATA=1")
			if scenario != "no-version" {
				command.Env = append(command.Env, "MXIOC_GO_EXPECT_CURRENT="+release)
			} else {
				command.Env = append(command.Env, "MXIOC_GO_EXPECT_CURRENT=")
			}
			output, err := command.CombinedOutput()
			if scenario == "success" {
				if err != nil {
					t.Fatal(err, string(output))
				}
				for _, path := range []string{data, auth, unit, filepath.Join(base, "current")} {
					if _, err := os.Lstat(path); !os.IsNotExist(err) {
						t.Fatal("purge left target", path)
					}
				}
			} else {
				if err == nil {
					t.Fatal("unsafe purge accepted")
				}
				if _, err := os.Stat(auth); err != nil {
					t.Fatal("credentials removed despite failure", err)
				}
				calls, _ := os.ReadFile(filepath.Join(root, "calls"))
				if scenario == "delete-failed" {
					if _, err := os.Stat(unit); !os.IsNotExist(err) {
						t.Fatal("service restored against partial data")
					}
					if strings.Contains(string(calls), "start ") {
						t.Fatal("service restarted after purge failure")
					}
					if !strings.Contains(string(output), "data removal incomplete") {
						t.Fatal("partial failure not reported", string(output))
					}
				} else {
					if strings.Contains(string(calls), "disable ") {
						t.Fatal("service stopped before purge preflight")
					}
					if _, err := os.Stat(unit); err != nil {
						t.Fatal("preflight changed unit")
					}
				}
			}
			raw, err := os.ReadFile(outside)
			if err != nil || string(raw) != "unrelated" {
				t.Fatal("followed child symlink")
			}
			if _, err := os.Stat(release); err != nil {
				t.Fatal("cached release deleted")
			}
		})
	}
}
