package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLegacyBandwidthRendererMatchesPythonAndClearRetries(t *testing.T) {
	policies := Record{"12": Record{"port": 24012, "protocols": []any{"tcp", "udp"}, "uploadKbps": 100, "downloadKbps": 4000},
		"2": Record{"port": 24002, "protocols": []any{"udp"}, "uploadKbps": 0, "downloadKbps": 100}}
	want := "table inet mxioc_bandwidth {\n" +
		"chain upload { type filter hook input priority -5; policy accept;\n" +
		"meta l4proto { tcp, udp } th dport 24012 limit rate over 12500 bytes/second burst 65536 bytes counter drop comment \"mxioc-12-upload\"\n" +
		"}\nchain download { type filter hook output priority -5; policy accept;\n" +
		"meta l4proto { udp } th sport 24002 limit rate over 12500 bytes/second burst 65536 bytes counter drop comment \"mxioc-2-download\"\n" +
		"meta l4proto { tcp, udp } th sport 24012 limit rate over 500000 bytes/second burst 100000 bytes counter drop comment \"mxioc-12-download\"\n}\n}\n"
	if got, err := legacyBandwidthRules(policies); err != nil || got != want {
		t.Fatalf("unexpected legacy rules: %v\n%s", err, got)
	}
	m, server := installFixture(t)
	m.mu.Lock()
	data, err := m.load()
	if err == nil {
		record, findErr := find(data, server)
		if findErr == nil {
			record["bandwidths"] = policies
			err = m.flush(data)
		} else {
			err = findErr
		}
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(_ context.Context, script string, _ int) (string, error) {
		calls++
		if !strings.Contains(script, "\nid=12\n") || strings.Contains(script, "flush ruleset") {
			t.Fatal("script changed an unowned rule")
		}
		if calls == 1 {
			return "", remoteExitError(76)
		}
		if calls == 2 {
			return "", errors.New("SSH disconnected after applying rules")
		}
		return "MXIOC_LEGACY_BANDWIDTH_CLEARED\n", nil
	}
	clear := func(port int) error {
		record, err := m.Record(server)
		if err != nil {
			return err
		}
		return m.clearLegacyBandwidth(context.Background(), record, 12, port, run)
	}
	if err := clear(24013); err == nil || calls != 0 {
		t.Fatal("incorrect port reached remote script")
	}
	for i := 0; i < 2; i++ {
		if err := clear(24012); err == nil {
			t.Fatal("uncertain cleanup accepted")
		}
	}
	if err := clear(24012); err != nil {
		t.Fatal(err)
	}
	if err := clear(24012); err != nil || calls != 3 {
		t.Fatal("confirmed cleanup must not run again", err)
	}
	record, err := m.Record(server)
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := record["bandwidths"].(Record)
	if len(stored) != 1 || stored["2"] == nil {
		t.Fatal("unrelated bandwidth policy was lost")
	}
}
