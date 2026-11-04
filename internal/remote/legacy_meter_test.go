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
	meters := row["meters"].(Record)
	if len(meters) != 1 || value(meters["2"]) != "24002" {
		t.Fatal("unrelated meter changed")
	}
}
