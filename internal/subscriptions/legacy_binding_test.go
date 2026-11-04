package subscriptions

import (
	"context"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func TestMigrateLegacyBindingSettlesOnceWithoutRewritingNodes(t *testing.T) {
	for _, source := range []string{"authenticated-client", "inbound"} {
		t.Run(source, func(t *testing.T) {
			testMigrateLegacyBinding(t, source, false)
		})
	}
	t.Run("standalone-inbound", func(t *testing.T) {
		testMigrateLegacyBinding(t, "inbound", true)
	})
}

type legacyCoreMigrationBackend struct {
	*fakeBackend
	enrolls int
	clears  int
}

func (b *legacyCoreMigrationBackend) ClearLegacyMeter(_ context.Context, server string, id, port int) error {
	if server != "s" || id != 1 || port != 24001 {
		panic("unexpected meter target")
	}
	b.clears++
	return nil
}

func (b *legacyCoreMigrationBackend) Record(id string) (Record, error) {
	row, err := b.fakeBackend.Record(id)
	row["meters"] = Record{"1": 24001}
	return row, err
}

func (b *legacyCoreMigrationBackend) Inbounds(ctx context.Context, id string) (Record, error) {
	row, err := b.fakeBackend.Inbounds(ctx, id)
	row["provisionInbounds"], row["readOnly"] = row["inbounds"], true
	return row, err
}

func (b *legacyCoreMigrationBackend) EnrollLegacyCoreUser(ctx context.Context, id string, binding Record) (Record, error) {
	b.enrolls++
	b.missingCounters = false
	return b.fakeBackend.SubscriptionUser(ctx, id, binding, "read", nil)
}

func testMigrateLegacyBinding(t *testing.T, source string, standalone bool) {
	t.Helper()
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
		"identityHash": hash, "up": 20, "down": 0, "counterSource": source, "multiplierUnits": 2000}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{binding}
		p["traffic"] = Record{"upload": 5, "enabled": true, "enforce": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	token := config.BindingToken("clash", stateBinding(t, c))
	core := &legacyCoreMigrationBackend{fakeBackend: backend}
	if standalone {
		backend.kind, backend.missingCounters = "xray", true
		c.Backend = core
	}
	backend.stats["legacy@example.test"] = Record{"up": int64(30), "down": int64(0), "source": "authenticated-client"}
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil {
		t.Fatal("migration accepted a shared credential")
	}
	if core.enrolls != 0 {
		t.Fatal("unverified ownership should not configure counters")
	}
	put(other, []any{})
	before, err := c.Repository.Raw("clash")
	if err != nil {
		t.Fatal(err)
	}
	result, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true)
	if err != nil {
		t.Fatal(err)
	}
	cutover := source == "inbound"
	if result["counterBaselineRebuilt"] != cutover {
		t.Fatal("unexpected baseline mode")
	}
	if standalone && (core.enrolls != 1 || result["legacyMeterRetained"] != true) {
		t.Fatal("expected one verified enrollment while keeping the old meter")
	}
	if standalone {
		token := config.BindingToken("clash", stateBinding(t, c))
		backend.missingCounters = true
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err == nil || core.clears != 0 {
			t.Fatal("missing authenticated counters should preserve the old meter")
		}
		backend.missingCounters = false
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err != nil || core.clears != 1 {
			t.Fatal("verified meter cleanup failed", err)
		}
		if stateBinding(t, c)["legacyMeterRetained"] != nil {
			t.Fatal("cleared meter is still marked present")
		}
	}
	if after, err := c.Repository.Raw("clash"); err != nil || before != after {
		t.Fatal("existing YAML was rewritten")
	}
	p, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	newBinding := stateBinding(t, c)
	want := "25"
	if cutover {
		want = "5"
	}
	if newBinding["scope"] != "user" || newBinding["counterSource"] != "authenticated-client" ||
		text(newBinding["up"]) != "30" || text(traffic(p)["upload"]) != want {
		t.Fatal("incorrect user binding or settlement")
	}
	if cutover {
		if err := c.applyReading("clash", newBinding, Record{"up": 33, "down": 0, "source": "authenticated-client"}); err != nil {
			t.Fatal(err)
		}
		p, err := c.Repository.State("clash")
		if err != nil || text(traffic(p)["upload"]) != "11" {
			t.Fatal("first post-migration sample must bill only the user delta", err)
		}
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
