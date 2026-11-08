package remote

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestLegacyMeterCleanupRequiresRemoteConfirmation(t *testing.T) {
	m, server := installFixture(t)
	m.mu.Lock()
	data, err := m.load()
	if err == nil {
		var row Record
		row, err = find(data, server)
		if err == nil {
			row["meters"] = Record{"1": 24001, "2": 24002}
			err = m.flush(data)
		}
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	run := func(_ context.Context, script string, _ int) (string, error) {
		calls++
		if strings.Contains(script, "delete table") || strings.Contains(script, "flush ruleset") ||
			!strings.Contains(script, "delete counter inet mxioc_usage up_") {
			t.Fatal("cleanup is not scoped to its rules and counters")
		}
		if calls == 1 {
			return "", remoteExitError(76)
		}
		if calls == 2 {
			return "", errors.New("SSH disconnected")
		}
		return "MXIOC_LEGACY_METER_CLEARED\n", nil
	}
	clear := func(port int) error {
		record, err := m.Record(server)
		if err != nil {
			return err
		}
		return m.clearLegacyMeter(context.Background(), record, 1, port, run)
	}
	if err := clear(24002); err == nil || calls != 0 {
		t.Fatal("accepted mismatched port")
	}
	for i := 0; i < 2; i++ {
		if err := clear(24001); err == nil {
			t.Fatal("accepted unconfirmed cleanup")
		}
		row, err := m.Record(server)
		if err != nil || row["meters"].(Record)["1"] == nil {
			t.Fatal("lost ownership before confirmation", err)
		}
	}
	if err := clear(24001); err != nil {
		t.Fatal(err)
	}
	if err := clear(24001); err != nil || calls != 3 {
		t.Fatal("confirmed cleanup retried remotely", err)
	}
	row, err := m.Record(server)
	if err != nil {
		t.Fatal(err)
	}
	if value(row["goMeterCleared"].(Record)["1"]) != "24001" {
		t.Fatal("cleanup receipt not persisted")
	}
	m, err = Open(m.root + "/..")
	if err != nil {
		t.Fatal(err)
	}
	if err := clear(24001); err != nil || calls != 3 {
		t.Fatal("receipt did not survive restart", err)
	}
	meters := row["meters"].(Record)
	if len(meters) != 1 || value(meters["2"]) != "24002" {
		t.Fatal("unrelated meter changed")
	}
}

// A busy panel must reach the same gate as panel edits, without dialing SSH.
// Before panel dispatch was implemented this returned a core-kind error instead.
func TestLegacyMeterPanelCleanupUsesPanelOperationGate(t *testing.T) {
	for _, kind := range []string{"3x-ui", "x-ui", "x-panel"} {
		t.Run(kind, func(t *testing.T) {
			m, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			payload := serverPayload()
			payload["installType"] = kind
			saved, err := m.Save(payload)
			if err != nil {
				t.Fatal(err)
			}
			id := value(saved["id"])
			gate := make(chan struct{}, 1)
			gate <- struct{}{}
			m.operations = map[string]chan struct{}{id: gate}
			err = m.ClearLegacyMeter(context.Background(), id, 1, 24001)
			if err == nil || !strings.Contains(err.Error(), "该服务器正在处理其他操作") {
				t.Fatal("cleanup bypassed panel gate", err)
			}
			if len(gate) != 1 {
				t.Fatal("cleanup released another operation's gate")
			}
		})
	}
}

func TestLegacyMeterMissingRegistryRequiresExactReceipt(t *testing.T) {
	m, server := installFixture(t)
	for _, test := range []struct {
		name            string
		meters, receipt any
		success         bool
	}{
		{"missing", nil, nil, false},
		{"empty", Record{}, Record{}, false},
		{"wrong-port", Record{}, Record{"1": 24002}, false},
		{"wrong-inbound", Record{}, Record{"2": 24001}, false},
		{"null-target", Record{"1": nil}, Record{"1": 24001}, false},
		{"matched", Record{}, Record{"1": 24001}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := m.Record(server)
			if err != nil {
				t.Fatal(err)
			}
			record["meters"], record["goMeterCleared"] = test.meters, test.receipt
			calls := 0
			err = m.clearLegacyMeter(context.Background(), record, 1, 24001, func(context.Context, string, int) (string, error) { calls++; return "", errors.New("unexpected SSH") })
			if (err == nil) != test.success || calls != 0 {
				t.Fatal("incorrect cleanup proof", err, calls)
			}
		})
	}
}
