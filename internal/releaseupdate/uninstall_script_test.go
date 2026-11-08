package releaseupdate

import (
	"github.com/Angasky/dingzhi-ban/deploy"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Execute only an isolated copy of the trusted installer, with systemctl
// replaced by a recorder. This never targets the machine's installed service.
func TestUninstallScriptPreservesDataAndRejectsChangedRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("installer requires root")
	}
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "preserve", true: "changed"}[changed], func(t *testing.T) {
			root := t.TempDir()
			base := filepath.Join(root, "go")
			release := filepath.Join(base, "releases", "v1.0.0")
			bin := filepath.Join(root, "bin")
			for _, dir := range []string{release, bin} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			unit := filepath.Join(root, "service")
			data := filepath.Join(root, "data")
			auth := filepath.Join(root, "auth")
			log := filepath.Join(root, "calls")
			for path, body := range map[string]string{unit: "unit", filepath.Join(release, "mxioc-go-release.service"): "unit", data: "subscription", auth: "credentials"} {
				if err := os.WriteFile(path, []byte(body), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(release, filepath.Join(base, "current")); err != nil {
				t.Fatal(err)
			}
			stub := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> '" + log + "'\n"
			if err := os.WriteFile(filepath.Join(bin, "systemctl"), []byte(stub), 0700); err != nil {
				t.Fatal(err)
			}
			script := strings.NewReplacer("base=/opt/mxioc-go", "base="+base, "data=/opt/mxioc-rule-manager", "data="+data, "auth=/etc/mxioc-rule-manager.auth.json", "auth="+auth, "unit=/etc/systemd/system/mxioc-go.service", "unit="+unit, "/run/lock/mxioc-go-release.lock", filepath.Join(root, "release.lock")).Replace(deploy.Installer)
			path := filepath.Join(root, "installer.sh")
			if err := os.WriteFile(path, []byte(script), 0600); err != nil {
				t.Fatal(err)
			}
			expected := release
			if changed {
				expected = filepath.Join(base, "releases", "v0.9.0")
			}
			command := exec.Command("bash", path, "uninstall")
			command.Env = append(os.Environ(), "PATH="+bin+":"+os.Getenv("PATH"), "MXIOC_GO_EXPECT_CURRENT="+expected)
			output, err := command.CombinedOutput()
			if changed {
				if err == nil {
					t.Fatal("changed release removed")
				}
				if _, err := os.Stat(log); !os.IsNotExist(err) {
					t.Fatal("systemctl called before version guard")
				}
				if _, err := os.Lstat(filepath.Join(base, "current")); err != nil {
					t.Fatal("changed release damaged")
				}
			} else {
				if err != nil {
					t.Fatal(err, string(output))
				}
				if _, err := os.Lstat(filepath.Join(base, "current")); !os.IsNotExist(err) {
					t.Fatal("current retained")
				}
				if _, err := os.Stat(unit); !os.IsNotExist(err) {
					t.Fatal("unit retained")
				}
			}
			for path, want := range map[string]string{data: "subscription", auth: "credentials", filepath.Join(release, "mxioc-go-release.service"): "unit"} {
				raw, err := os.ReadFile(path)
				if err != nil || string(raw) != want {
					t.Fatal("preserved data changed", err)
				}
			}
		})
	}
}
