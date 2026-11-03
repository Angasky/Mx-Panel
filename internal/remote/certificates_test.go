package remote

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func certificateFixture(t *testing.T) (*Manager, string) {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	return m, value(record["id"])
}
func waitCertificate(t *testing.T, m *Manager, server, id string) Record {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		job, err := m.CertificateJob(server, id)
		if err != nil {
			t.Fatal(err)
		}
		if job["status"] == "succeeded" || job["status"] == "failed" {
			return job
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("certificate worker did not finish")
	return nil
}
func TestCertificateShellAndValidation(t *testing.T) {
	for _, domain := range []string{"", "*.example.com", "https://example.com", "example.com;id", "example..com", "-x.example.com", "127.0.0.1", "你好.example.com"} {
		if _, err := certificateScript(Record{"host": "198.51.100.20"}, domain); err == nil {
			t.Fatal("invalid domain", domain)
		}
	}
	if _, err := certificateScript(Record{"host": "198.51.100.20", "installType": "x-ui;id"}, "node.example.com"); err == nil {
		t.Fatal("invalid service")
	}
	script, err := certificateScript(Record{"host": "198.51.100.20", "installType": "3x-ui"}, " Node.Example.COM. ")
	if err != nil || !strings.Contains(script, "cert_domain='node.example.com'") || !strings.Contains(script, "sha256sum -c") || strings.Contains(script, "python") {
		t.Fatal("script validation", err)
	}
	// Ensure this embedded script remains aligned with the production-tested
	// Python reference without executing Python during Go tests or at runtime.
	source, err := os.ReadFile("../../certificate_manager.py")
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile("(?s)return prefix \\+ r'''(.*?)'''").FindSubmatch(source)
	if len(match) != 2 {
		t.Fatal("reference shell missing")
	}
	commit := regexp.MustCompile("ACME_COMMIT = '([a-f0-9]+)'").FindSubmatch(source)
	digest := regexp.MustCompile("ACME_SHA256 = '([a-f0-9]+)'").FindSubmatch(source)
	if len(commit) != 2 || len(digest) != 2 {
		t.Fatal("reference pin missing")
	}
	expected := strings.TrimLeft(strings.ReplaceAll(string(match[1]), "\r\n", "\n"), "\n")
	expected = strings.ReplaceAll(expected, "__ACME_URL__", "https://raw.githubusercontent.com/acmesh-official/acme.sh/"+string(commit[1])+"/acme.sh")
	expected = strings.ReplaceAll(expected, "__ACME_SHA__", string(digest[1]))
	if strings.ReplaceAll(expected, "\r\n", "\n") != strings.ReplaceAll(certificateShell, "\r\n", "\n") {
		t.Fatal("Go and production-tested certificate scripts diverged")
	}
}

func TestCertificateDeduplicationBusyGuardsAndSuccess(t *testing.T) {
	m, id := certificateFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	m.certificateRun = func(ctx context.Context, c Connection, script string) (string, error) {
		calls.Add(1)
		close(started)
		<-release
		return "MXIOC_CERT_READY\n", nil
	}
	job, err := m.StartCertificate(id, "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	<-started
	repeated, err := m.StartCertificate(id, "NODE.EXAMPLE.COM.")
	if err != nil || job["id"] != repeated["id"] {
		t.Fatal("duplicate task", err)
	}
	if _, err = m.StartCertificate(id, "other.example.com"); err == nil {
		t.Fatal("parallel job on same host")
	}
	if _, err = m.Save(Record{"id": id, "name": "changed"}); err == nil {
		t.Fatal("edited active certificate server")
	}
	if _, err = m.ForgetServer(id, func(_ Record, commit func() error) (Record, error) { return Record{}, commit() }); err == nil {
		t.Fatal("removed active certificate server")
	}
	if _, err = m.WithPanel(context.Background(), id, func(*Panel, Record) (any, error) { t.Fatal("panel mutation overlapped certificate"); return nil, nil }); err == nil {
		t.Fatal("concurrent panel operation accepted")
	}
	close(release)
	done := waitCertificate(t, m, id, value(job["id"]))
	if done["status"] != "succeeded" || calls.Load() != 1 {
		t.Fatal(done)
	}
	paths, err := m.ReadyCertificate(id, value(job["id"]), "node.example.com")
	if err != nil || paths["certFile"] != "/etc/mxioc-certificates/node.example.com/fullchain.pem" {
		t.Fatal(paths, err)
	}
	if _, err = m.ReadyCertificate(id, value(job["id"]), "other.example.com"); err == nil {
		t.Fatal("accepted foreign domain")
	}
	list, err := m.List()
	if err != nil || len(list[0]["certificateDomains"].([]any)) != 1 {
		t.Fatal("domain candidate not persisted", err)
	}
	reopened, err := Open(filepath.Dir(m.root))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = reopened.CertificateJob(id, value(job["id"])); err == nil {
		t.Fatal("adopted job after restart")
	}
	record, _ := reopened.Record(id)
	if len(record["certificateDomains"].([]any)) != 1 {
		t.Fatal("restart lost domain candidate")
	}
}

func TestCertificateCancellationAndRedactedFailure(t *testing.T) {
	m, id := certificateFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	m.SetJobContext(ctx)
	started := make(chan struct{})
	m.certificateRun = func(ctx context.Context, c Connection, script string) (string, error) {
		close(started)
		<-ctx.Done()
		return "ssh: " + c.Password + " panel: sample-panel-password", errors.New("cancelled")
	}
	job, err := m.StartCertificate(id, "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	<-started
	cancel()
	done := waitCertificate(t, m, id, value(job["id"]))
	if done["status"] != "failed" || strings.Contains(value(done["error"]), "sample-ssh-password") || strings.Contains(value(done["error"]), "sample-panel-password") {
		t.Fatal("failure leaked secret", done)
	}
	if _, ok := done["keyFile"]; ok {
		t.Fatal("failure returned ready paths")
	}
	if _, err = m.StartCertificate(id, "node.example.com"); err == nil {
		t.Fatal("accepted job after shutdown")
	}
}

func TestCertificateRequiresMarkerAndChecksScope(t *testing.T) {
	m, id := certificateFixture(t)
	m.certificateRun = func(context.Context, Connection, string) (string, error) {
		return "certificate command returned zero but did not verify", nil
	}
	job, err := m.StartCertificate(id, "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if done := waitCertificate(t, m, id, value(job["id"])); done["status"] != "failed" {
		t.Fatal("false success", done)
	}
	payload := serverPayload()
	payload["host"] = "198.51.100.21"
	other, err := m.Save(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = m.CertificateJob(value(other["id"]), value(job["id"])); err == nil {
		t.Fatal("task crossed server scope")
	}
	if _, err = m.Save(Record{"id": id, "host": "198.51.100.22"}); err != nil {
		t.Fatal(err)
	}
	if _, err = m.CertificateJob(id, value(job["id"])); err == nil {
		t.Fatal("stale job accepted after rebind")
	}
}

func TestCertificateGlobalConcurrencyLimit(t *testing.T) {
	m, first := certificateFixture(t)
	ids := []string{first}
	for i := 0; i < 4; i++ {
		payload := serverPayload()
		payload["host"] = "198.51.100." + strconv.Itoa(30+i)
		row, err := m.Save(payload)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, value(row["id"]))
	}
	release := make(chan struct{})
	m.certificateRun = func(ctx context.Context, _ Connection, _ string) (string, error) {
		select {
		case <-release:
			return "MXIOC_CERT_READY\n", nil
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	jobs := []Record{}
	for _, id := range ids[:4] {
		job, err := m.StartCertificate(id, "node.example.com")
		if err != nil {
			t.Fatal(err)
		}
		jobs = append(jobs, job)
	}
	if _, err := m.StartCertificate(ids[4], "node.example.com"); err == nil {
		t.Fatal("unbounded certificate concurrency")
	}
	close(release)
	for i, job := range jobs {
		if done := waitCertificate(t, m, ids[i], value(job["id"])); done["status"] != "succeeded" {
			t.Fatal(done)
		}
	}
	job, err := m.StartCertificate(ids[4], "node.example.com")
	if err != nil {
		t.Fatal("slots not released", err)
	}
	if done := waitCertificate(t, m, ids[4], value(job["id"])); done["status"] != "succeeded" {
		t.Fatal(done)
	}
}
