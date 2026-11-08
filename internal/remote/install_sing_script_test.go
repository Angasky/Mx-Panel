package remote

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Run the real installer with isolated paths and command fixtures. No network,
// service manager, system binary or administrator-owned configuration is changed.
func TestSingInstallBuildAndRollback(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash = "C:/Program Files/Git/bin/bash.exe"
	}
	for _, scenario := range []string{"fresh", "arm64", "fresh-service", "existing", "checksum", "build", "capability", "config", "service", "inactive-service", "term-service", "rollback-failure"} {
		t.Run(scenario, func(t *testing.T) {
			root := filepath.ToSlash(t.TempDir())
			fresh := scenario == "fresh" || scenario == "arm64" || scenario == "fresh-service"
			write := func(name, body string) {
				t.Helper()
				path := filepath.Join(root, name)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte(body), 0755); err != nil {
					t.Fatal(err)
				}
			}
			for _, dir := range []string{"mock", "tmp", "usr/bin", "etc/sing-box", "var/lock"} {
				if err := os.MkdirAll(filepath.Join(root, dir), 0700); err != nil {
					t.Fatal(err)
				}
			}
			original := "original-binary\n"
			originalConfig := "{\"inbounds\":[],\"outbounds\":[],\"log\":{\"level\":\"error\"}}\n"
			if !fresh {
				write("usr/bin/sing-box", original)
				write("etc/sing-box/config.json", originalConfig)
				write("unit", "existing-unit")
				if scenario != "inactive-service" {
					write("active", "")
					write("enabled", "")
				}
			}
			write("mock/id", "#!/bin/bash\necho 0\n")
			write("mock/uname", "#!/bin/bash\nif [ \"$SCENARIO\" = arm64 ];then echo aarch64;else echo x86_64;fi\n")
			write("mock/flock", "#!/bin/bash\nexit 0\n")
			write("mock/sleep", "#!/bin/bash\nexit 0\n")
			write("mock/sha256sum", `#!/bin/bash
set -eu
read -r sum archive
if [ "$SCENARIO" = arm64 ]; then test "$sum" = 3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797; else test "$sum" = ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5; fi
test -s "$archive"
test "$SCENARIO" != checksum
`)
			write("mock/curl", `#!/bin/bash
set -eu
url='';dest=''
while [ "$#" -gt 0 ]; do case "$1" in https://*) url="$1";; -o) shift;dest="$1";; esac;shift;done
if [ "$SCENARIO" = arm64 ]; then test "$url" = https://go.dev/dl/go1.26.10.linux-arm64.tar.gz;else test "$url" = https://go.dev/dl/go1.26.10.linux-amd64.tar.gz;fi
printf 'verified-toolchain-fixture' > "$dest"
`)
			write("mock/tar", `#!/bin/bash
set -eu
while [ "$#" -gt 0 ]; do if [ "$1" = -C ]; then shift;dest="$1";fi;shift;done
mkdir -p "$dest/go/bin"
cp "$FIXTURE_ROOT/fake-go" "$dest/go/bin/go"
chmod 755 "$dest/go/bin/go"
`)
			write("fake-go", `#!/bin/bash
set -eu
test "$SCENARIO" != build
test "$GOTOOLCHAIN" = local
test "$CGO_ENABLED" = 0
test "$GOMAXPROCS" = 2
test "$GOSUMDB" = sum.golang.org
case "$*" in *with_quic,with_utls,with_v2ray_api*sing-box@v1.14.4) ;; *) exit 33;; esac
cp "$FIXTURE_ROOT/managed-binary" "$GOBIN/sing-box"
chmod 755 "$GOBIN/sing-box"
`)
			write("managed-binary", `#!/bin/bash
set -eu
# managed-binary marker
case "$1" in
version) if [ "$SCENARIO" = capability ]; then echo 'with_quic'; else echo '1.14.4 with_quic with_utls with_v2ray_api'; fi ;;
check) test "$SCENARIO" != config ;;
*) exit 34 ;;
esac
`)
			write("mock/systemctl", `#!/bin/bash
set -eu
case "$1" in
cat) test -f "$FIXTURE_ROOT/unit" ;;
is-active) test -f "$FIXTURE_ROOT/active" ;;
is-enabled) test -f "$FIXTURE_ROOT/enabled" ;;
enable) touch "$FIXTURE_ROOT/enabled" ;;
disable) rm -f "$FIXTURE_ROOT/enabled" ;;
stop) rm -f "$FIXTURE_ROOT/active" ;;
daemon-reload) exit 0 ;;
restart)
 case "$SCENARIO" in rollback-failure) exit 35;; term-service) if [ ! -f "$FIXTURE_ROOT/failed-once" ]; then touch "$FIXTURE_ROOT/failed-once"; kill -TERM "$PPID"; exit 35;fi;; service|inactive-service|fresh-service) if [ ! -f "$FIXTURE_ROOT/failed-once" ]; then touch "$FIXTURE_ROOT/failed-once";exit 35;fi;; esac
 touch "$FIXTURE_ROOT/active" ;;
*) exit 36 ;;
esac
`)
			script, err := coreInstallScript("sing-box", "")
			if err != nil {
				t.Fatal(err)
			}
			script = strings.NewReplacer("/usr/bin/sing-box", root+"/usr/bin/sing-box", "/etc/sing-box", root+"/etc/sing-box", "/var/lock", root+"/var/lock", "/etc/systemd/system", root+"/etc/systemd/system", "/var/lib/sing-box", root+"/var/lib/sing-box", "/tmp/mxioc-", root+"/tmp/mxioc-").Replace(script)
			// Keep mkdir /usr/bin inside the fixture as well.
			script = strings.ReplaceAll(script, "mkdir -p /usr/bin", "mkdir -p '"+root+"/usr/bin'")
			script = "if command -v cygpath >/dev/null; then FIXTURE_ROOT=$(cygpath -u \"$FIXTURE_ROOT\");export FIXTURE_ROOT;fi\nexport PATH=\"$FIXTURE_ROOT/mock:$PATH\"\n" + script
			cmd := exec.Command(bash, "-s")
			cmd.Stdin = strings.NewReader(script)
			cmd.Env = append(os.Environ(), "FIXTURE_ROOT="+root, "SCENARIO="+scenario)
			output, runErr := cmd.CombinedOutput()
			success := scenario == "fresh" || scenario == "arm64" || scenario == "existing"
			if (runErr == nil) != success {
				t.Fatal("installer result mismatch", runErr, string(output))
			}
			if scenario == "fresh-service" {
				for _, name := range []string{"usr/bin/sing-box", "etc/sing-box/config.json", "etc/systemd/system/sing-box.service", "active", "enabled"} {
					if _, err := os.Stat(filepath.Join(root, name)); !os.IsNotExist(err) {
						t.Fatal("fresh failure retained installed resource", name, err, string(output))
					}
				}
				if !strings.Contains(string(output), "MXIOC_ROLLBACK_RESTORED") {
					t.Fatal("fresh failure rollback not confirmed", string(output))
				}
				return
			}
			binary, err := os.ReadFile(filepath.Join(root, "usr/bin/sing-box"))
			if err != nil {
				t.Fatal(err)
			}
			config, err := os.ReadFile(filepath.Join(root, "etc/sing-box/config.json"))
			if err != nil {
				t.Fatal(err)
			}
			if success {
				if !strings.Contains(string(binary), "managed-binary marker") || !strings.Contains(string(output), "MXIOC_STAGE=installed") {
					t.Fatal("managed build not installed", string(output))
				}
				if fresh && (strings.Contains(string(config), "vendor-config") || !strings.Contains(string(config), `"inbounds":[]`)) {
					t.Fatal("vendor sample config retained")
				}
				if scenario == "existing" && string(config) != originalConfig {
					t.Fatal("existing configuration changed")
				}
			} else {
				if string(binary) != original || string(config) != originalConfig {
					t.Fatal("failure changed existing binary/config", string(output))
				}
				stage := "build"
				if scenario == "checksum" {
					stage = "download"
				}
				if scenario == "service" || scenario == "inactive-service" || scenario == "term-service" || scenario == "rollback-failure" {
					stage = "service"
				}
				if !strings.Contains(string(output), "MXIOC_STAGE="+stage+"\n") {
					t.Fatal("did not reach intended failure stage", string(output))
				}
				if strings.Contains(string(output), "MXIOC_STAGE=installed") {
					t.Fatal("failed install marked complete")
				}
				if scenario == "service" || scenario == "inactive-service" || scenario == "term-service" || scenario == "rollback-failure" {
					if scenario == "rollback-failure" {
						if !strings.Contains(string(output), "MXIOC_ROLLBACK_FAILED") || !strings.Contains(string(output), "Recovery copies retained") {
							t.Fatal(string(output))
						}
					} else if !strings.Contains(string(output), "MXIOC_ROLLBACK_RESTORED") {
						t.Fatal("rollback not confirmed", string(output))
					}
				}
			}
			for _, state := range []string{"active", "enabled"} {
				_, err := os.Stat(filepath.Join(root, state))
				want := success || !fresh && scenario != "inactive-service"
				if (err == nil) != want {
					t.Fatal("service state not preserved", state, string(output))
				}
			}
			entries, _ := os.ReadDir(filepath.Join(root, "tmp"))
			if scenario == "rollback-failure" {
				if len(entries) < 2 {
					t.Fatal("rollback recovery copies lost")
				}
			} else if len(entries) != 0 {
				t.Fatal("temporary toolchain/config retained")
			}
		})
	}
}
