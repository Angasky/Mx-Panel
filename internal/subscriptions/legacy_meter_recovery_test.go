package subscriptions

import (
	"context"
	"errors"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

type completedMeterBackend struct {
	*fakeBackend
	receipt       any
	registry      any
	include       bool
	reads, clears int
}

func (b *completedMeterBackend) Record(id string) (Record, error) {
	r, err := b.fakeBackend.Record(id)
	r["goMeterCleared"] = b.receipt
	if b.include {
		r["meters"] = b.registry
	}
	return r, err
}
func (b *completedMeterBackend) SubscriptionUser(context.Context, string, Record, string, Record) (Record, error) {
	b.reads++
	return nil, errors.New("counter API offline")
}
func (b *completedMeterBackend) ClearLegacyMeter(context.Context, string, int, int) error {
	b.clears++
	return errors.New("must not replay cleanup")
}

func TestLegacyMeterCleanupFinishesAfterRegistryCommitAndRestart(t *testing.T) {
	for _, test := range []struct {
		name     string
		include  bool
		registry any
		retained bool
		success  bool
	}{
		{"confirmed-removed", true, Record{"2": 24002}, true, true},
		{"empty-registry", true, Record{}, true, true},
		{"still-registered", true, Record{"1": 24001}, true, false},
		{"null-target", true, Record{"1": nil}, true, false},
		{"missing-registry", false, nil, true, false},
		{"null-registry", true, nil, true, false},
		{"malformed-registry", true, "{}", true, false},
		{"no-retained-proof", true, Record{}, false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			c, base, root := controllerFixture(t)
			binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "scope": "user", "status": "active", "counterSource": "authenticated-client", "userHash": "verified-user", "identityHash": "verified-inbound", "legacyMeterRetained": test.retained}
			if err := c.Repository.UpdateState("clash", func(p Record) error {
				p["remoteNodes"] = []any{binding}
				p["traffic"] = Record{"upload": 17, "download": 23}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			backend := &completedMeterBackend{fakeBackend: base, include: test.include, registry: test.registry, receipt: Record{"1": 24001}}
			restarted := New(&config.Repository{Root: root}, backend)
			token := config.BindingToken("clash", stateBinding(t, restarted))
			result, err := restarted.ClearLegacyMeter(context.Background(), "clash", 0, token, true)
			if (err == nil) != test.success {
				t.Fatal(result, err)
			}
			if backend.clears != 0 {
				t.Fatal("replayed remote mutation")
			}
			if test.success {
				if result["reconciled"] != true || backend.reads != 0 || stateBinding(t, restarted)["legacyMeterRetained"] != nil {
					t.Fatal("local cleanup not reconciled")
				}
			} else if backend.reads != 1 || stateBinding(t, restarted)["legacyMeterRetained"] != test.retained {
				t.Fatal("ambiguous cleanup lost marker")
			}
			state, _ := restarted.Repository.State("clash")
			if text(traffic(state)["upload"]) != "17" || text(traffic(state)["download"]) != "23" {
				t.Fatal("reconciliation changed billing")
			}
		})
	}
}

func TestLegacyMeterReconciliationStillChecksOwnership(t *testing.T) {
	for _, mode := range []string{"revoked", "pending-delete", "wrong-token", "unconfirmed", "other-legacy-owner"} {
		t.Run(mode, func(t *testing.T) {
			c, base, _ := controllerFixture(t)
			binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "scope": "user", "status": "active", "counterSource": "authenticated-client", "legacyMeterRetained": true}
			if mode == "revoked" {
				binding["status"] = "revoked"
			}
			if mode == "pending-delete" {
				binding["inboundDeletePending"] = Record{}
			}
			if err := c.Repository.UpdateState("clash", func(p Record) error { p["remoteNodes"] = []any{binding}; return nil }); err != nil {
				t.Fatal(err)
			}
			if mode == "other-legacy-owner" {
				other, err := c.Repository.CreateProfile(Record{"name": "other"})
				if err != nil {
					t.Fatal(err)
				}
				if err := c.Repository.UpdateState(text(other["id"]), func(p Record) error {
					p["remoteNodes"] = []any{Record{"serverId": "s", "inboundId": 1, "status": "active"}}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
			}
			b := &completedMeterBackend{fakeBackend: base, include: true, registry: Record{}, receipt: Record{"1": 24001}}
			c.Backend = b
			token := config.BindingToken("clash", stateBinding(t, c))
			if mode == "wrong-token" {
				token = "0000000000000000000000000000000000000000000000000000000000000000"
			}
			if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, mode != "unconfirmed"); err == nil {
				t.Fatal("invalid reconciliation accepted")
			}
			if stateBinding(t, c)["legacyMeterRetained"] != true || b.reads != 0 || b.clears != 0 {
				t.Fatal("invalid reconciliation changed state")
			}
		})
	}
}

func TestLegacyMeterReconciliationRequiresPersistedPortReceipt(t *testing.T) {
	for _, receipt := range []any{nil, Record{}, Record{"1": 24002}, Record{"2": 24001}, Record{"1": nil}, "{}"} {
		c, base, _ := controllerFixture(t)
		binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "scope": "user", "status": "active", "counterSource": "authenticated-client", "legacyMeterRetained": true}
		if err := c.Repository.UpdateState("clash", func(p Record) error { p["remoteNodes"] = []any{binding}; return nil }); err != nil {
			t.Fatal(err)
		}
		b := &completedMeterBackend{fakeBackend: base, include: true, registry: Record{}, receipt: receipt}
		c.Backend = b
		token := config.BindingToken("clash", stateBinding(t, c))
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err == nil {
			t.Fatal("unproven cleanup reconciled")
		}
		if stateBinding(t, c)["legacyMeterRetained"] != true || b.reads != 1 || b.clears != 0 {
			t.Fatal("missing receipt lost retained marker")
		}
	}
}
