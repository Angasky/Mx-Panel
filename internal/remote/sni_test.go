package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type fixtureSNISession struct {
	dns, reality string
	tlsFail      bool
	probes       atomic.Int32
	closed       atomic.Int32
	beforeProbe  func()
}

func (f *fixtureSNISession) Close() error { f.closed.Add(1); return nil }
func (f *fixtureSNISession) Run(ctx context.Context, script string, limit int) (string, error) {
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if strings.Contains(script, "MXIOC_SNI_DNS") {
		return f.dns, nil
	}
	if strings.HasPrefix(script, "curl ") {
		if f.tlsFail {
			return "", fmt.Errorf("TLS failure")
		}
		return "MXIOC_TLS 0.0123\n", nil
	}
	f.probes.Add(1)
	if f.beforeProbe != nil {
		f.beforeProbe()
	}
	return f.reality, nil
}
func sniFixture(t *testing.T) (*Manager, string, *fixtureSNISession) {
	t.Helper()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	f := &fixtureSNISession{dns: "one.example.com 8.8.8.8\ntwo.example.com 1.1.1.1\n", reality: "MXIOC_REALITY_RESULT 0 OK\nMXIOC_REALITY_RESULT 1 FAIL\n"}
	scanner := m.sniState()
	scanner.open = func(context.Context, Connection) (sniSession, error) { return f, nil }
	return m, value(record["id"]), f
}
func TestSNITwoStageResultsCacheForceAndExpiry(t *testing.T) {
	m, id, f := sniFixture(t)
	domains := []string{"one.example.com", "two.example.com"}
	for call := 0; call < 2; call++ {
		result, err := m.ScanSNI(context.Background(), id, domains, false)
		if err != nil {
			t.Fatal(err)
		}
		rows := result["results"].([]Record)
		if rows[0]["ok"] != true || rows[0]["realityVerified"] != true || rows[0]["verifiedAddress"] != "8.8.8.8" || rows[0]["latencyMs"] != 12.3 {
			t.Fatal(rows)
		}
		if rows[1]["ok"] != false || rows[1]["verifiedAddress"] != nil || rows[1]["error"] == nil {
			t.Fatal("failed Reality became selectable")
		}
		if call == 1 && rows[0]["cached"] != true {
			t.Fatal("did not use verified cache")
		}
	}
	if f.probes.Load() != 1 || f.closed.Load() != 2 {
		t.Fatal("session/probe reuse failed")
	}
	if _, err := m.ScanSNI(context.Background(), id, domains, true); err != nil {
		t.Fatal(err)
	}
	if f.probes.Load() != 2 {
		t.Fatal("force did not revalidate")
	}
	scanner := m.sniState()
	now := time.Now().Add(16 * time.Second)
	scanner.now = func() time.Time { return now }
	// Only the failed target expires after 15 seconds; the successful target lasts ten minutes.
	f.reality = "MXIOC_REALITY_RESULT 0 OK\n"
	if _, err := m.ScanSNI(context.Background(), id, domains, false); err != nil {
		t.Fatal(err)
	}
	if f.probes.Load() != 3 {
		t.Fatal("failed result did not expire")
	}
}
func TestSNINeverPromotesTLSOnlyOrMissingMarkers(t *testing.T) {
	for _, marker := range []string{"", "MXIOC_REALITY_ERROR kernel\n", "MXIOC_REALITY_ERROR tools\n", "MXIOC_REALITY_RESULT 0 OK\nMXIOC_REALITY_RESULT 0 OK\n", "MXIOC_REALITY_RESULT 99 OK\n"} {
		m, id, f := sniFixture(t)
		f.reality = marker
		result, err := m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false)
		if err != nil {
			t.Fatal(err)
		}
		row := result["results"].([]Record)[0]
		if row["ok"] != false || row["verifiedAddress"] != nil || len(m.sniState().cache) != 0 {
			t.Fatal("incomplete proof cached as usable", marker, row)
		}
	}
	m, id, f := sniFixture(t)
	f.reality = "MXIOC_REALITY_ERROR ports\n"
	if _, err := m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false); err != nil {
		t.Fatal(err)
	}
	if f.probes.Load() != 2 {
		t.Fatal("port collision was not retried exactly once")
	}
}
func TestSNIPrivateDNSAndTLSFailuresAreHidden(t *testing.T) {
	for _, dns := range []string{"one.example.com 8.8.8.8\none.example.com 127.0.0.1\n", "one.example.com 169.254.169.254\n", ""} {
		m, id, f := sniFixture(t)
		f.dns = dns
		result, err := m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false)
		if err != nil {
			t.Fatal(err)
		}
		if result["results"].([]Record)[0]["ok"] != false || f.probes.Load() != 0 {
			t.Fatal("nonpublic DNS reached Reality")
		}
	}
	m, id, f := sniFixture(t)
	f.tlsFail = true
	result, err := m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false)
	if err != nil || result["results"].([]Record)[0]["ok"] != false || f.probes.Load() != 0 {
		t.Fatal("TLS failure reached Reality", err)
	}
}
func TestSNIConnectionChangeDiscardedCancellationAndSlotBounds(t *testing.T) {
	m, id, f := sniFixture(t)
	f.beforeProbe = func() {
		_, err := m.Save(Record{"id": id, "host": "198.51.100.11"})
		if err != nil {
			t.Error(err)
		}
	}
	if _, err := m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false); err == nil {
		t.Fatal("connection change returned old result")
	}
	if len(m.sniState().cache) != 0 {
		t.Fatal("stale identity cached")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := m.ScanSNI(ctx, id, []string{"one.example.com"}, false); err == nil {
		t.Fatal("cancellation ignored")
	}
	scanner := newSNIScanner()
	for i := 0; i < 128; i++ {
		if _, err := scanner.serverSlot(fmt.Sprint(i)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := scanner.serverSlot("129"); err == nil {
		t.Fatal("in-use slot evicted")
	}
	scanner.servers["0"].users = 0
	if _, err := scanner.serverSlot("129"); err != nil {
		t.Fatal("idle slot not evicted")
	}
	for i := 0; i < 2100; i++ {
		scanner.remember(sniCacheKey{domain: fmt.Sprint(i)}, true)
	}
	if len(scanner.cache) > 2048 {
		t.Fatal("unbounded cache")
	}
}
func TestSNIPerServerConcurrencyAndValidation(t *testing.T) {
	m, id, _ := sniFixture(t)
	scanner := m.sniState()
	started := make(chan struct{}, 3)
	release := make(chan struct{})
	scanner.open = func(ctx context.Context, c Connection) (sniSession, error) {
		started <- struct{}{}
		select {
		case <-release:
			return &fixtureSNISession{}, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	var work sync.WaitGroup
	for i := 0; i < 3; i++ {
		work.Add(1)
		go func() { defer work.Done(); m.ScanSNI(context.Background(), id, []string{"one.example.com"}, false) }()
	}
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(time.Second):
			close(release)
			t.Fatal("two scans did not start")
		}
	}
	select {
	case <-started:
		close(release)
		t.Fatal("more than two SSH scans per server")
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	work.Wait()
	for _, domains := range [][]string{nil, {"127.0.0.1"}, {"host;id.example.com"}, {"https://example.com"}, make([]string, 21)} {
		if _, err := sniDomains(domains); err == nil {
			t.Fatal("invalid SNI accepted", domains)
		}
	}
	normalized, err := sniDomains([]string{"ONE.EXAMPLE.COM.", "one.example.com"})
	if err != nil || len(normalized) != 1 {
		t.Fatal(normalized, err)
	}
}

func probeConfigs(t *testing.T, script string) (Record, Record) {
	t.Helper()
	read := func(marker string) Record {
		_, tail, ok := strings.Cut(script, "<<'"+marker+"' >/dev/null 2>&1 &\n")
		if !ok {
			t.Fatal("missing config")
		}
		wire, _, _ := strings.Cut(tail, "\n"+marker)
		var doc Record
		if json.Unmarshal([]byte(wire), &doc) != nil {
			t.Fatal("invalid JSON")
		}
		return doc
	}
	return read("MXIOC_TEST_SERVER"), read("MXIOC_TEST_CLIENT")
}
func TestRealityProbeScriptIsolationAndRouting(t *testing.T) {
	script, err := realityProbeScript([]sniTarget{{"one.example.com", "8.8.8.8"}, {"two.example.com", "2606:4700:4700::1111"}})
	if err != nil {
		t.Fatal(err)
	}
	server, client := probeConfigs(t, script)
	ports := map[string]bool{}
	for _, config := range []Record{server, client} {
		for _, value := range config["inbounds"].([]any) {
			in := value.(map[string]any)
			port := in["port"].(float64)
			if port <= 20000 || port > 65535 || ports[fmt.Sprint(port)] || in["listen"] != "127.0.0.1" {
				t.Fatal("unsafe/duplicate listener", in)
			}
			ports[fmt.Sprint(port)] = true
		}
	}
	if len(client["routing"].(map[string]any)["rules"].([]any)) != 2 {
		t.Fatal("missing per-inbound route")
	}
	for _, required := range []string{"for attempt in 1 2; do", "trap cleanup EXIT", "timeout 75", "/proc/net/udp", "--socks5-hostname", "blackhole"} {
		if !strings.Contains(script, required) {
			t.Fatal("missing isolation invariant", required)
		}
	}
	for _, forbidden := range []string{"python", "systemctl", "nft ", "iptables", "/etc/xray", "curl -k"} {
		if strings.Contains(script, forbidden) {
			t.Fatal("probe touched production", forbidden)
		}
	}
	if _, err := realityProbeScript([]sniTarget{{"one.example.com", "127.0.0.1"}}); err == nil {
		t.Fatal("private target accepted")
	}
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash = "C:/Program Files/Git/bin/bash.exe"
	}
	command := exec.Command(bash, "-n")
	command.Stdin = strings.NewReader(script)
	if out, err := command.CombinedOutput(); err != nil {
		t.Fatal("shell syntax", err, string(out))
	}
	if _, ok := sniTLSLatency("MXIOC_TLS NaN\n"); ok {
		t.Fatal("nonfinite latency accepted")
	}
	if _, ok := sniTLSLatency("MXIOC_TLS -1\n"); ok {
		t.Fatal("negative latency accepted")
	}
}

func TestSNIForceFailureDoesNotReviveOldSuccessAndSingBoxIsHidden(t *testing.T) {
	m, id, f := sniFixture(t)
	domains := []string{"one.example.com"}
	f.reality = "MXIOC_REALITY_RESULT 0 OK\n"
	if _, err := m.ScanSNI(context.Background(), id, domains, false); err != nil {
		t.Fatal(err)
	}
	f.reality = "MXIOC_REALITY_ERROR kernel\n"
	for _, force := range []bool{true, false} {
		result, err := m.ScanSNI(context.Background(), id, domains, force)
		if err != nil || result["results"].([]Record)[0]["ok"] != false {
			t.Fatal("old success revived", result, err)
		}
	}
	if f.probes.Load() != 3 {
		t.Fatal("failed force left old verified cache")
	}
	payload := serverPayload()
	payload["id"] = id
	payload["installType"] = "sing-box"
	delete(payload, "panelAddress")
	if _, err := m.Save(payload); err != nil {
		t.Fatal(err)
	}
	before := f.probes.Load()
	result, err := m.ScanSNI(context.Background(), id, domains, false)
	if err != nil || result["results"].([]Record)[0]["ok"] != false || f.probes.Load() != before {
		t.Fatal("unsupported verifier became selectable", result, err)
	}
}

func TestSNICancellationClosesOnlyItsSSHConnection(t *testing.T) {
	connection, _ := sshFixture(t)
	scanner := newSNIScanner()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first, err := scanner.open(ctx, connection)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	other, err := scanner.open(context.Background(), connection)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	closed := make(chan struct{})
	go func() { first.(*sshSNISession).client.Wait(); close(closed) }()
	cancel()
	select {
	case <-closed:
	case <-time.After(time.Second):
		t.Fatal("canceled scan retained SSH connection")
	}
	output, err := other.Run(context.Background(), "echo isolated", 4096)
	if err != nil || !strings.Contains(output, "SSH proof") || strings.Contains(output, connection.Password) {
		t.Fatal("cancel closed unrelated session or leaked password", err, output)
	}
}
