package subscriptions

import (
	"context"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func TestMissingRemoteInboundRemovedEvenWithoutQuotaEnforcement(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1, 2}); err != nil {
		t.Fatal(err)
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["enforce"] = false; return nil }); err != nil {
		t.Fatal(err)
	}
	b.rows = b.rows[1:]
	if _, err := c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 || stateBinding(t, c)["status"] != "missing" {
		t.Fatal("orphan node retained")
	}
	source, err := c.Repository.PublicSubscription(strings.Repeat("a", 50), c.Now())
	if err != nil || len(source.Document["proxies"].([]any)) != 1 {
		t.Fatal("public subscription still contains deleted node", err)
	}
	targets, err := c.Repository.ImportTargets("s", []int{1, 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(targets[0]["importedInboundIds"].([]int)) != 1 {
		t.Fatal("missing node was hidden as imported", targets)
	}
}

func TestOfflineInventoryAndStaleGenerationNeverDelete(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	b.offline = true
	if _, err := c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("offline treated as deletion")
	}
	b.offline = false
	observed, _ := c.Repository.BindingSnapshot("s")
	p, err := c.Repository.CreateProfile(config.Document{"name": "new", "templateId": "blank"})
	if err != nil {
		t.Fatal(err)
	}
	id := text(p["id"])
	if _, err = c.Batch(context.Background(), id, "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ReconcileServer(context.Background(), "s", Record{"inbounds": []any{}}, observed); err != nil {
		t.Fatal(err)
	}
	latest, _ := c.Repository.Snapshot(id)
	if len(latest["nodes"].([]any)) != 1 {
		t.Fatal("stale inventory removed new binding")
	}
}

func TestManuallyDeletedUserRemovesOnlyThatSubscriptionsNode(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	p, _ := c.Repository.CreateProfile(config.Document{"name": "peer", "templateId": "blank"})
	peer := text(p["id"])
	if _, err := c.Batch(context.Background(), peer, "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	binding := stateBinding(t, c)
	settings := b.rows[0]["settings"].(Record)
	next := []any{}
	for _, v := range settings["clients"].([]any) {
		if v.(map[string]any)["email"] != binding["userEmail"] {
			next = append(next, v)
		}
	}
	settings["clients"] = next
	if _, err := c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	first, _ := c.Repository.Snapshot("clash")
	other, _ := c.Repository.Snapshot(peer)
	if len(first["nodes"].([]any)) != 0 || len(other["nodes"].([]any)) != 1 {
		t.Fatal("user cleanup crossed subscriptions")
	}
}

func TestReusedLocalNameIsPreservedAndBadInventoryRejected(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	if err := c.Repository.Mutate("clash", func(d Record) error {
		d["proxies"].([]any)[0].(map[string]any)["password"] = "manual-replacement"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.rows = []Record{}
	if _, err := c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("deleted different node sharing old name")
	}
	for _, bad := range []Record{{}, {"inbounds": nil}, {"inbounds": []any{Record{"id": 1}, Record{"id": 1}}}, {"inbounds": []any{Record{"id": true}}}} {
		if _, _, err := inventoryRows(bad); err == nil {
			t.Fatal("malformed inventory accepted")
		}
	}
}

type missingCoreBackend struct {
	*fakeBackend
	inventory Record
}

func (b *missingCoreBackend) Inbounds(context.Context, string) (Record, error) {
	return b.inventory, nil
}

func TestStandaloneReconciliationRequiresExplicitIdentityProof(t *testing.T) {
	for _, background := range []bool{false, true} {
		name := "refresh"
		if background {
			name = "background"
		}
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			c, base, _ := controllerFixture(t)
			if _, err := c.Batch(ctx, "clash", "s", []int{1, 2}); err != nil {
				t.Fatal(err)
			}
			if err := c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["enforce"] = false; return nil }); err != nil {
				t.Fatal(err)
			}
			binding := stateBinding(t, c)
			name := binding["importedNames"].([]any)[0]
			if err := c.Repository.Mutate("clash", func(doc Record) error {
				groups, _ := doc["proxy-groups"].([]any)
				doc["proxy-groups"] = append(groups, Record{"name": "fallback-fixture", "type": "fallback",
					"proxies": []any{name}, "url": "https://example.net/", "interval": 30})
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if err := c.Repository.UpdateState("clash", func(p Record) error {
				p["failovers"] = []any{Record{"name": "fallback-fixture"}}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			observed, err := c.Repository.BindingSnapshot("s")
			if err != nil {
				t.Fatal(err)
			}
			core := &missingCoreBackend{fakeBackend: base}
			c.Backend = core
			reconcile := func(rows ...any) {
				t.Helper()
				core.inventory = Record{"readOnly": true, "inbounds": rows}
				if background {
					if _, err := c.Sync(ctx, "clash"); err != nil {
						t.Fatal(err)
					}
				} else if _, err := c.ReconcileServer(ctx, "s", core.inventory, observed); err != nil {
					t.Fatal(err)
				}
			}
			assertNodes := func(want int) {
				t.Helper()
				snapshot, err := c.Repository.Snapshot("clash")
				if err != nil || len(snapshot["nodes"].([]any)) != want {
					t.Fatalf("expected %d nodes: %v", want, err)
				}
			}
			reconcile(Record{"id": 1, "coreStatus": "disabled", "missingUserIdentity": binding["identityHash"]})
			assertNodes(2)
			reconcile(Record{"id": 1, "coreStatus": "missing", "missingUserIdentity": strings.Repeat("f", 64)})
			assertNodes(2)
			reconcile(Record{"id": 1, "coreStatus": "missing", "missingUserIdentity": binding["identityHash"]})
			assertNodes(1)
			if got := stateBinding(t, c)["status"]; got != "missing" {
				t.Fatal("verified missing node not marked", got)
			}
			snapshot, err := c.Repository.Snapshot("clash")
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range objects(snapshot["groups"]) {
				if group["name"] == "fallback-fixture" {
					policy, _ := group["config"].(Record)
					proxies, _ := policy["proxies"].([]any)
					if len(proxies) != 1 || proxies[0] != "REJECT" {
						t.Fatal("empty managed failover should reject traffic", proxies)
					}
					return
				}
			}
			t.Fatal("managed failover disappeared")
		})
	}
}
