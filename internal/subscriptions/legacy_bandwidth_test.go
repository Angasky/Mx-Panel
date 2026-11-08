package subscriptions

import (
	"context"
	"errors"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
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

type bandwidthReceiptBackend struct {
	*bandwidthCleanupBackend
	policies, receipt any
}

func (b *bandwidthReceiptBackend) Record(id string) (Record, error) {
	r, err := b.fakeBackend.Record(id)
	r["bandwidths"], r["goBandwidthCleared"] = b.policies, b.receipt
	return r, err
}

func TestClearLegacyBandwidthReconcilesReceiptWithoutRemote(t *testing.T) {
	for _, test := range []struct {
		name              string
		policies, receipt any
		success           bool
	}{
		{"confirmed", Record{}, Record{"1": 24001}, true},
		{"unrelated-policy", Record{"2": Record{"port": 24002}}, Record{"1": 24001}, true},
		{"no-policy-registry", nil, Record{"1": 24001}, false},
		{"no-receipt", Record{}, nil, false},
		{"wrong-port", Record{}, Record{"1": 24002}, false},
		{"wrong-id", Record{}, Record{"2": 24001}, false},
		{"policy-present", Record{"1": Record{"port": 24001}}, Record{"1": 24001}, false},
		{"policy-null", Record{"1": nil}, Record{"1": 24001}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, base, root := controllerFixture(t)
			if err := c.Repository.UpdateState("clash", func(p Record) error {
				p["remoteNodes"] = []any{Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active", "bandwidth": Record{"uploadKbps": 1000}}}
				p["traffic"] = Record{"upload": 19}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			b := &bandwidthReceiptBackend{bandwidthCleanupBackend: &bandwidthCleanupBackend{fakeBackend: base, fail: true}, policies: test.policies, receipt: test.receipt}
			restarted := New(&config.Repository{Root: root}, b)
			_, err := restarted.SetBandwidth(context.Background(), "clash", "s", 1, 0, 0)
			if (err == nil) != test.success {
				t.Fatal(err)
			}
			rate := text(stateBinding(t, restarted)["bandwidth"].(Record)["uploadKbps"])
			if test.success && (b.calls != 0 || rate != "0") {
				t.Fatal("receipt replayed remote cleanup")
			}
			if !test.success && (b.calls != 1 || rate != "1000") {
				t.Fatal("invalid receipt changed state")
			}
			state, _ := restarted.Repository.State("clash")
			if text(traffic(state)["upload"]) != "19" {
				t.Fatal("cleanup changed billing")
			}
		})
	}
}

func TestLegacyBandwidthClearRejectsConflictingOwnership(t *testing.T) {
	for _, sameProfile := range []bool{false, true} {
		for _, status := range []string{"active", "provisioning", "pending-delete", "revoked"} {
			c, base, _ := controllerFixture(t)
			if err := c.Repository.UpdateState("clash", func(p Record) error {
				p["remoteNodes"] = []any{Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active", "bandwidth": Record{"uploadKbps": 1000}}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			owner := "clash"
			if !sameProfile {
				other, err := c.Repository.CreateProfile(Record{"name": "other"})
				if err != nil {
					t.Fatal(err)
				}
				owner = text(other["id"])
			}
			if err := c.Repository.UpdateState(owner, func(p Record) error {
				conflicting := Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": status, "scope": "user"}
				if status == "pending-delete" {
					conflicting["status"] = "missing"
					conflicting["inboundDeletePending"] = Record{}
				}
				list, _ := p["remoteNodes"].([]any)
				p["remoteNodes"] = append(list, conflicting)
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			backend := &bandwidthCleanupBackend{fakeBackend: base}
			c.Backend = backend
			_, err := c.SetBandwidth(context.Background(), "clash", "s", 1, 0, 0)
			if status == "revoked" {
				if err != nil || backend.calls != 1 {
					t.Fatal("finished history blocked cleanup", err)
				}
			} else {
				if err == nil || backend.calls != 0 {
					t.Fatal("conflicting ownership reached remote cleanup", sameProfile, status, err)
				}
				if text(stateBinding(t, c)["bandwidth"].(Record)["uploadKbps"]) != "1000" {
					t.Fatal("conflict changed local rate")
				}
			}
		}
	}
}
