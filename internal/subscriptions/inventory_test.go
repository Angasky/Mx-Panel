package subscriptions

import (
	"context"
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
