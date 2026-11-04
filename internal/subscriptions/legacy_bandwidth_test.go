package subscriptions

import (
	"context"
	"errors"
	"testing"
)

type bandwidthCleanupBackend struct {
	*fakeBackend
	calls int
	fail  bool
}

func (b *bandwidthCleanupBackend) ClearLegacyBandwidth(_ context.Context, _ string, _, _ int) error {
	b.calls++
	if b.fail {
		return errors.New("remote confirmation pending")
	}
	return nil
}

func TestClearLegacyBandwidthOnlyUpdatesConfirmedDedicatedBinding(t *testing.T) {
	ctx := context.Background()
	c, base, _ := controllerFixture(t)
	if _, err := c.Batch(ctx, "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	b := &bandwidthCleanupBackend{fakeBackend: base}
	c.Backend = b
	if _, err := c.SetBandwidth(ctx, "clash", "s", 1, 0, 0); err == nil || b.calls != 0 {
		t.Fatal("shared user must never trigger legacy port cleanup")
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		row := objects(p["remoteNodes"])[0]
		delete(row, "scope")
		row["bandwidth"] = Record{"uploadKbps": 1000}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.fail = true
	if _, err := c.SetBandwidth(ctx, "clash", "s", 1, 0, 0); err == nil || b.calls != 1 {
		t.Fatal("uncertain remote cleanup accepted")
	}
	if text(stateBinding(t, c)["bandwidth"].(Record)["uploadKbps"]) != "1000" {
		t.Fatal("unconfirmed cleanup changed local binding")
	}
	b.fail = false
	if _, err := c.SetBandwidth(ctx, "clash", "s", 1, 0, 0); err != nil {
		t.Fatal(err)
	}
	if text(stateBinding(t, c)["bandwidth"].(Record)["uploadKbps"]) != "0" {
		t.Fatal("confirmed cleanup did not update binding")
	}
}
