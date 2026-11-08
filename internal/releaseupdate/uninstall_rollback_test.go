package releaseupdate

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/deploy"
)

// Paths and systemctl are replaced before executing any installer code.
// All mutations are confined to t.TempDir; no host service is inspected.
func TestUninstallRollbackAtEachDestructiveStage(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer requires root")
	}
	for _, failure := range []string{"disable", "remove", "reload", "terminate", "restore"} {
		for _, active := range []bool{false, true} {
			for _, enabled := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/active=%t/enabled=%t", failure, active, enabled), func(t *testing.T) {
					root := t.TempDir()
					base := filepath.Join(root, "go")
					release := filepath.Join(base, "releases", "v1.0.0")
					bin := filepath.Join(root, "bin")
					for _, dir := range []string{release, bin} {
						if err := os.MkdirAll(dir, 0700); err != nil {
							t.Fatal(err)
						}
					}
					write := func(path, body string, mode os.FileMode) {
						t.Helper()
						if err := os.WriteFile(path, []byte(body), mode); err != nil {
							t.Fatal(err)
						}
						if err := os.Chmod(path, mode); err != nil {
							t.Fatal(err)
						}
					}
					unit := filepath.Join(root, "unit")
					data := filepath.Join(root, "data")
					auth := filepath.Join(root, "auth")
					write(unit, "original unit", 0640)
					write(filepath.Join(release, "mxioc-go-release.service"), "original unit", 0640)
					write(data, "subscription", 0600)
					write(auth, "credentials", 0600)
					// Preserve the literal relative target, not just its resolved directory.
					if err := os.Symlink("releases/v1.0.0", filepath.Join(base, "current")); err != nil {
						t.Fatal(err)
					}
					if active {
						write(filepath.Join(root, "active"), "1", 0600)
					}
					if enabled {
						write(filepath.Join(root, "enabled"), "1", 0600)
					}
					write(filepath.Join(bin, "systemctl"), `#!/bin/bash
set -eu
case "$1" in
 is-active) [[ -f "$TEST_ROOT/active" ]] ;;
 is-enabled) [[ -f "$TEST_ROOT/enabled" ]] ;;
 disable)
  /bin/rm -f "$TEST_ROOT/active" "$TEST_ROOT/enabled"
  if [[ "$TEST_FAILURE" == terminate ]]; then kill -TERM "$PPID"; fi
  [[ "$TEST_FAILURE" != disable ]]
  ;;
 daemon-reload)
  if [[ "$TEST_FAILURE" == reload || "$TEST_FAILURE" == restore ]]; then
   if [[ ! -f "$TEST_ROOT/reload-failed" ]]; then
    touch "$TEST_ROOT/reload-failed"; exit 1
   fi
   [[ "$TEST_FAILURE" != restore ]]
  fi
  ;;
 enable) touch "$TEST_ROOT/enabled" ;;
 start) touch "$TEST_ROOT/active" ;;
 *) exit 98 ;;
esac
`, 0700)
					write(filepath.Join(bin, "rm"), `#!/bin/bash
set -eu
if [[ "$TEST_FAILURE" == remove && "$*" == "-- $TEST_ROOT/unit $TEST_ROOT/go/current" ]]; then
 /bin/rm -- "$TEST_ROOT/unit"
 exit 1
fi
exec /bin/rm "$@"
`, 0700)
					script := strings.NewReplacer("base=/opt/mxioc-go", "base="+base, "data=/opt/mxioc-rule-manager", "data="+data, "auth=/etc/mxioc-rule-manager.auth.json", "auth="+auth, "unit=/etc/systemd/system/mxioc-go.service", "unit="+unit, "/run/lock/mxioc-go-release.lock", filepath.Join(root, "lock")).Replace(deploy.Installer)
					path := filepath.Join(root, "installer.sh")
					write(path, script, 0600)
					command := exec.Command("bash", path, "uninstall")
					command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "TEST_ROOT="+root, "TEST_FAILURE="+failure, "MXIOC_GO_EXPECT_CURRENT="+release)
					output, err := command.CombinedOutput()
					if err == nil {
						t.Fatal("partial uninstall reported success", string(output))
					}
					for path, want := range map[string]string{unit: "original unit", data: "subscription", auth: "credentials"} {
						raw, err := os.ReadFile(path)
						if err != nil || string(raw) != want {
							t.Fatal("recovery lost file", path, err, string(output))
						}
					}
					info, err := os.Stat(unit)
					if err != nil || info.Mode().Perm() != 0640 {
						t.Fatal("unit permissions changed")
					}
					link, err := os.Readlink(filepath.Join(base, "current"))
					if err != nil || link != "releases/v1.0.0" {
						t.Fatal("release link not restored", err)
					}
					stages, _ := filepath.Glob(filepath.Join(base, ".remove.*"))
					if failure == "restore" {
						if len(stages) != 1 || !strings.Contains(string(output), "restoration is incomplete") {
							t.Fatal("incomplete restore not retained", string(output))
						}
						raw, err := os.ReadFile(filepath.Join(stages[0], "unit"))
						if err != nil || string(raw) != "original unit" {
							t.Fatal("recovery unit lost")
						}
					} else {
						if len(stages) != 0 || !strings.Contains(string(output), "service state restored") {
							t.Fatal("rollback incomplete", string(output))
						}
						for path, want := range map[string]bool{"active": active, "enabled": enabled} {
							_, err := os.Stat(filepath.Join(root, path))
							if (err == nil) != want {
								t.Fatal("previous service state not restored", path, string(output))
							}
						}
					}
				})
			}
		}
	}
}
