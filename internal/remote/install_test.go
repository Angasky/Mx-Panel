package remote

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func installFixture(t *testing.T) (*Manager, string) {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	p := serverPayload()
	p["installType"] = "xray"
	p["connectionMode"] = "install"
	delete(p, "panelAddress")
	p["coreConfig"] = `{"inbounds":[],"outbounds":[],"password":"fixture-config-secret"}`
	row, err := m.Save(p)
	if err != nil {
		t.Fatal(err)
	}
	return m, value(row["id"])
}
func waitInstall(t *testing.T, m *Manager, id string) Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := m.InstallJob(id)
		if err != nil {
			t.Fatal(err)
		}
		if job["status"] != "running" {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("worker did not finish")
	return nil
}
func TestNativeInstallTaskRunsOnceLocksAndRedacts(t *testing.T) {
	m, id := installFixture(t)
	release := make(chan struct{})
	calls := 0
	m.installRun = func(ctx context.Context, c Connection, script string) (string, error) {
		calls++
		<-release
		return "fixture-config-secret " + c.Password + "\nMXIOC_STAGE=installed\n", nil
	}
	if _, err := m.StartInstall(id, false); err == nil {
		t.Fatal("confirmation ignored")
	}
	job, err := m.StartInstall(id, true)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.StartInstall(id, true); err == nil {
		t.Fatal("duplicate install accepted")
	}
	if _, err = m.Save(Record{"id": id, "name": "changed"}); err == nil {
		t.Fatal("connection changed during install")
	}
	close(release)
	finished := waitInstall(t, m, value(job["id"]))
	if finished["status"] != "succeeded" || calls != 1 || strings.Contains(value(finished["log"]), "fixture-config-secret") || strings.Contains(value(finished["log"]), "sample-ssh-password") {
		t.Fatal(finished)
	}
}
func TestNativeInstallFailureAndRecoveryNeverReplay(t *testing.T) {
	m, id := installFixture(t)
	m.installRun = func(context.Context, Connection, string) (string, error) {
		return "MXIOC_STAGE=config\nvalidation failure", errors.New("fixture failure")
	}
	job, err := m.StartInstall(id, true)
	if err != nil {
		t.Fatal(err)
	}
	failed := waitInstall(t, m, value(job["id"]))
	if failed["status"] != "failed" || failed["stage"] != "config" {
		t.Fatal(failed)
	}
	m.mu.Lock()
	data, _ := m.load()
	data["jobs"].([]any)[0].(Record)["status"] = "running"
	err = m.flush(data)
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if err = m.RecoverInstallJobs(); err != nil {
		t.Fatal(err)
	}
	recovered, _ := m.InstallJob(value(job["id"]))
	if recovered["status"] != "interrupted" {
		t.Fatal(recovered)
	}
}
func TestNativeInstallScriptsValidateWithoutPython(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		script, err := coreInstallScript(kind, `{"inbounds":[],"outbounds":[]}`)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(script, "python") || strings.Contains(script, "__MXIOC_CONFIG64__") || !strings.Contains(script, "flock -n 9") {
			t.Fatal("bad native script")
		}
		bash, err := exec.LookPath("bash")
		if err != nil {
			bash = "C:/Program Files/Git/bin/bash.exe"
		}
		cmd := exec.Command(bash, "-n")
		cmd.Stdin = strings.NewReader(script)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatal(err, string(out))
		}
	}
	if _, err := coreInstallScript("xray", `{"inbounds":{}}`); err == nil {
		t.Fatal("invalid config accepted")
	}
}
