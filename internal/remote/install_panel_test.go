package remote

import (
	"os/exec"
	"strings"
	"testing"
)

func TestPanelInstallerQuotesCredentialsAndDomain(t *testing.T) {
	for _, domain := range []string{"", "panel.example.com"} {
		script, err := panelInstallScript(Record{"installType": "3x-ui", "domain": domain, "panelUser": "admin ' special"}, "p'$(echo fixture);word")
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(script, "__MXIOC_") || !strings.Contains(script, "flock -n 9") {
			t.Fatal("unexpanded installer")
		}
		if domain == "" && !strings.Contains(script, "XUI_AUTO=1") {
			t.Fatal("automatic mode missing")
		}
		if domain != "" && !strings.Contains(script, "XUI_DOMAIN='panel.example.com'") {
			t.Fatal("domain not quoted")
		}
		binary, err := exec.LookPath("bash")
		if err != nil {
			binary = "C:/Program Files/Git/bin/bash.exe"
		}
		cmd := exec.Command(binary, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	if _, err := panelInstallScript(Record{"installType": "x-panel"}, "password"); err == nil {
		t.Fatal("existing-only panel install accepted")
	}
	if _, err := panelInstallScript(Record{"installType": "3x-ui", "panelUser": "admin", "domain": "bad;domain"}, "password"); err == nil {
		t.Fatal("bad domain accepted")
	}
}
