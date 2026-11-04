package subscriptions

import (
	"context"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func TestMigrateLegacyBindingSettlesOnceWithoutRewritingNodes(t *testing.T) {
	c, backend, _ := controllerFixture(t)
	row := backend.rows[0]
	client := Record{"email": "legacy@example.test", "auth": "legacy-test-secret", "enable": true}
	row["settings"].(Record)["clients"] = []any{client}
	server, _ := backend.Record("s")
	nodes, err := remote.InboundNodes(row, server)
	if err != nil || len(nodes) != 1 {
		t.Fatal(err)
	}
	put := func(profile string, nodes []any) {
		t.Helper()
		if err := c.Repository.Mutate(profile, func(doc Record) error {
			doc["proxies"] = nodes
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	put("clash", []any{nodes[0]})
	copied, err := c.Repository.CreateProfile(Record{"name": "other"})
	if err != nil {
		t.Fatal(err)
	}
	other := text(copied["id"])
	put(other, []any{nodes[0]})
	hash, err := remote.LegacyInboundIdentity(row)
	if err != nil {
		t.Fatal(err)
	}
	binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active",
		"identityHash": hash, "up": 20, "down": 0, "counterSource": "authenticated-client", "multiplierUnits": 2000}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{binding}
		p["traffic"] = Record{"upload": 5, "enabled": true, "enforce": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	token := config.BindingToken("clash", stateBinding(t, c))
	backend.stats["legacy@example.test"] = Record{"up": int64(30), "down": int64(0), "source": "authenticated-client"}
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil {
		t.Fatal("migration accepted a shared credential")
	}
	put(other, []any{})
	before, err := c.Repository.Raw("clash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err != nil {
		t.Fatal(err)
	}
	if after, err := c.Repository.Raw("clash"); err != nil || before != after {
		t.Fatal("existing YAML was rewritten")
	}
	p, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	newBinding := stateBinding(t, c)
	if newBinding["scope"] != "user" || text(newBinding["up"]) != "30" || text(traffic(p)["upload"]) != "25" {
		t.Fatal("incorrect user binding or settlement")
	}
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil {
		t.Fatal("stale migration token accepted")
	}
	for _, op := range backend.ops {
		if op != "read" {
			t.Fatal("migration modified remote user")
		}
	}
}
