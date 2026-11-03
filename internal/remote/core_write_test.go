package remote

import (
	"os/exec"
	"strings"
	"testing"
)

func TestCoreWriterChecksIdentityAndHasRollback(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		script, err := CoreWriteScript(kind, []byte(`{"inbounds":[],"outbounds":[]}`), Record{"inbounds": []any{}, "outbounds": []any{}, "secret": "fixture-private"})
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(script, "fixture-private") || strings.Contains(script, "python") || !strings.Contains(script, "MXIOC_CORE_ROLLED_BACK") || strings.Count(script, "exit 76") != 2 {
			t.Fatal("transaction safeguards missing")
		}
		bash, err := exec.LookPath("bash")
		if err != nil {
			bash = "C:/Program Files/Git/bin/bash.exe"
		}
		command := exec.Command(bash, "-n")
		command.Stdin = strings.NewReader(script)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatal(err, string(output))
		}
	}
	if _, err := CoreWriteScript("xray;id", []byte(`{}`), Record{}); err == nil {
		t.Fatal("invalid core accepted")
	}
	if _, err := CoreWriteScript("xray", []byte(`{}`), Record{"inbounds": "bad"}); err == nil {
		t.Fatal("invalid inbound list accepted")
	}
}
