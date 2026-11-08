package subscriptions

import (
	"context"
	"encoding/json"
	"testing"
)

func TestServerImportLiveReadDedupAndGuards(t *testing.T) {
	c, b, _ := controllerFixture(t)
	b.rows = []Record{{"id": 1, "port": 8080, "protocol": "http", "enable": true, "remark": "proxy", "settings": Record{"accounts": []any{Record{"user": "alice", "pass": "remote-password"}}}}}
	ctx := context.Background()
	payload := Record{"bind": false, "links": []any{"http://forged@example.invalid"}}
	result, err := c.ImportServerInbound(ctx, "clash", "s", 1, payload)
	if err != nil || result["added"] != 1 {
		t.Fatal(result, err)
	}
	result, err = c.ImportServerInbound(ctx, "clash", "s", 1, payload)
	if err != nil || result["added"] != 0 || result["existing"] != 1 {
		t.Fatal("retry duplicated import", result, err)
	}
	snap, _ := c.Repository.Snapshot("clash")
	node := snap["nodes"].([]any)[0].(Record)["config"].(Record)
	if node["server"] != "192.0.2.1" || node["password"] != "remote-password" {
		t.Fatal("browser-supplied credentials used", node)
	}
	for _, bad := range []Record{{"bind": "false"}, {"bind": true}, {"indices": []any{json.Number("1")}}, {"indices": []any{json.Number("0"), json.Number("0")}}, {"indices": []any{true}}} {
		if _, err := c.ImportServerInbound(ctx, "clash", "s", 1, bad); err == nil {
			t.Fatal("unsafe import accepted", bad)
		}
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{Record{"serverId": "s", "inboundId": 1, "status": "revoked"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportServerInbound(ctx, "clash", "s", 1, payload); err == nil {
		t.Fatal("revoked ownership ignored")
	}
}

func TestServerImportLimitsCancellationAndOffline(t *testing.T) {
	c, b, _ := controllerFixture(t)
	b.rows = []Record{{"id": 1, "port": 8080, "protocol": "http", "enable": true, "remark": "proxy", "settings": Record{}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ImportServerInbound(ctx, "clash", "s", 1, Record{}); err == nil {
		t.Fatal("canceled import succeeded")
	}
	b.offline = true
	if _, err := c.ImportServerInbound(context.Background(), "clash", "s", 1, Record{}); err == nil {
		t.Fatal("offline import succeeded")
	}
	b.offline = false
	if err := c.Repository.UpdateState("clash", func(p Record) error { p["traffic"] = Record{"enabled": true, "enforce": true}; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportServerInbound(context.Background(), "clash", "s", 1, Record{}); err == nil {
		t.Fatal("uncontrolled node imported into enforced subscription")
	}
	snap, _ := c.Repository.Snapshot("clash")
	if len(snap["nodes"].([]any)) != 0 {
		t.Fatal("failed import wrote nodes")
	}
}

type readonlyImportBackend struct {
	*fakeBackend
	snapshot Record
}

func (b *readonlyImportBackend) Inbounds(context.Context, string) (Record, error) {
	return b.snapshot, nil
}

func TestServerImportVerifiedCoreLinks(t *testing.T) {
	for _, status := range []string{"present", "unverified", "missing", "changed"} {
		t.Run(status, func(t *testing.T) {
			c, b, _ := controllerFixture(t)
			c.Backend = &readonlyImportBackend{b, Record{"readOnly": true, "inbounds": []any{Record{
				"id": 1, "enable": true, "coreStatus": status,
				"shareLinks": []any{"http://alice:verified@192.0.2.1:8080#core"},
			}}}}
			result, err := c.ImportServerInbound(context.Background(), "clash", "s", 1, Record{"links": []any{"http://forged@wrong.invalid"}})
			if status == "present" {
				if err != nil || result["added"] != 1 {
					t.Fatal(result, err)
				}
			} else if err == nil {
				t.Fatal("unverified core imported")
			}
			snapshot, err := c.Repository.Snapshot("clash")
			if err != nil {
				t.Fatal(err)
			}
			nodes := snapshot["nodes"].([]any)
			if status != "present" {
				if len(nodes) != 0 {
					t.Fatal("failed verification wrote nodes")
				}
			} else if nodes[0].(Record)["config"].(Record)["password"] != "verified" {
				t.Fatal("client credentials used")
			}
		})
	}
}

func TestServerImportOwnedInboundUsesIsolatedUser(t *testing.T) {
	c, b, _ := controllerFixture(t)
	ctx := context.Background()
	if result, err := c.Batch(ctx, "clash", "s", []int{1}); err != nil || result["succeeded"] != 1 {
		t.Fatal(result, err)
	}
	owner := stateBinding(t, c)
	other, err := c.Repository.CreateProfile(Record{"name": "other"})
	if err != nil {
		t.Fatal(err)
	}
	profile := text(other["id"])
	for i := 0; i < 2; i++ {
		result, err := c.ImportServerInbound(ctx, profile, "s", 1, Record{"bind": true, "links": []any{"http://forged@wrong.invalid"}})
		if err != nil {
			t.Fatal(result, err)
		}
	}
	state, err := c.Repository.State(profile)
	if err != nil {
		t.Fatal(err)
	}
	bindings := objects(state["remoteNodes"])
	if len(bindings) != 1 || bindings[0]["scope"] != "user" || bindings[0]["userHash"] == owner["userHash"] || b.adds != 2 {
		t.Fatal("users were shared or duplicated")
	}
	if traffic(state)["enforce"] != true {
		t.Fatal("import bypassed enforcement")
	}
	c.started.Store(false)
	if _, err := c.ImportServerInbound(ctx, profile, "s", 1, Record{}); err == nil {
		t.Fatal("import accepted without metering")
	}
}
