package subscriptions

import (
	"context"
	"errors"
	"reflect"
	"strings"
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
	t.Run("panel-retained-meter", func(t *testing.T) {
		testMigrateLegacyBinding(t, "inbound", false, true)
	})
	t.Run("cleared-bandwidth-receipt", func(t *testing.T) {
		testMigrateLegacyBinding(t, "inbound", false, false, true)
	})
}

type legacyCoreMigrationBackend struct {
	*fakeBackend
	enrolls    int
	clears     int
	clearError error
}

func (b *legacyCoreMigrationBackend) ClearLegacyMeter(_ context.Context, server string, id, port int) error {
	if server != "s" || id != 1 || port != 24001 {
		panic("unexpected meter target")
	}
	b.clears++
	return b.clearError
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

func testMigrateLegacyBinding(t *testing.T, source string, standalone bool, panelMeter ...bool) {
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
	recoverBandwidth := len(panelMeter) > 1 && panelMeter[1]
	if recoverBandwidth {
		binding["bandwidth"] = Record{"uploadKbps": 1000}
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{binding}
		p["traffic"] = Record{"upload": 5, "enabled": true, "enforce": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	token := config.BindingToken("clash", stateBinding(t, c))
	core := &legacyCoreMigrationBackend{fakeBackend: backend}
	withMeter := standalone || len(panelMeter) > 0 && panelMeter[0]
	if standalone {
		backend.kind, backend.missingCounters = "xray", true
		c.Backend = core
	} else if withMeter {
		c.Backend = &legacyPanelMigrationBackend{legacyCoreMigrationBackend: core}
	}
	if recoverBandwidth {
		c.Backend = &bandwidthReceiptBackend{bandwidthCleanupBackend: &bandwidthCleanupBackend{fakeBackend: backend, fail: true}, policies: Record{}, receipt: Record{"1": 24001}}
	}
	backend.stats["legacy@example.test"] = Record{"up": int64(30), "down": int64(0), "source": "authenticated-client"}
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil {
		t.Fatal("migration accepted a shared credential")
	}
	if core.enrolls != 0 {
		t.Fatal("unverified ownership should not configure counters")
	}
	if recoverBandwidth && text(stateBinding(t, c)["bandwidth"].(Record)["uploadKbps"]) != "1000" {
		t.Fatal("failed migration changed local bandwidth before commit")
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
	if withMeter {
		if result["legacyMeterRetained"] != true {
			t.Fatal("retained meter not reported")
		}
		token := config.BindingToken("clash", stateBinding(t, c))
		backend.missingCounters = true
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err == nil || core.clears != 0 {
			t.Fatal("missing authenticated counters should preserve the old meter")
		}
		backend.missingCounters = false
		core.clearError = errors.New("SSH result unknown")
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err == nil || core.clears != 1 {
			t.Fatal("ambiguous cleanup reported success", err)
		}
		if stateBinding(t, c)["legacyMeterRetained"] != true {
			t.Fatal("lost retained meter before confirmed cleanup")
		}
		core.clearError = nil
		if _, err := c.ClearLegacyMeter(context.Background(), "clash", 0, token, true); err != nil || core.clears != 2 {
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
	if recoverBandwidth && text(newBinding["bandwidth"].(Record)["uploadKbps"]) != "0" {
		t.Fatal("migration retained cleared rate")
	}
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
	// Simulate a lost success response and a fresh controller after restart.
	restarted := New(&config.Repository{Root: c.Repository.Root}, c.Backend)
	beforeReplay, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	beforeOps, beforeEnrolls := len(backend.ops), core.enrolls
	replayed, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, token, true)
	if err != nil || replayed["reused"] != true || replayed["counterBaselineRebuilt"] != cutover {
		t.Fatal("completed migration was not recoverable", replayed, err)
	}
	afterReplay, err := c.Repository.State("clash")
	if err != nil || !reflect.DeepEqual(beforeReplay, afterReplay) || len(backend.ops) != beforeOps || core.enrolls != beforeEnrolls {
		t.Fatal("completed retry changed billing or remote user", err)
	}
	if _, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, strings.Repeat("0", 64), true); err == nil {
		t.Fatal("unrelated migration token accepted")
	}
	if _, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, token, false); err == nil {
		t.Fatal("replay skipped confirmation")
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		objects(p["remoteNodes"])[0]["status"] = "revoked"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil {
		t.Fatal("receipt accepted after revocation")
	}
	for _, op := range backend.ops {
		if op != "read" {
			t.Fatal("migration modified remote user")
		}
	}
}

// A panel exposes its own client counters; it must not use core enrollment.
type legacyPanelMigrationBackend struct{ *legacyCoreMigrationBackend }

func (b *legacyPanelMigrationBackend) Inbounds(ctx context.Context, id string) (Record, error) {
	return b.fakeBackend.Inbounds(ctx, id)
}

func TestCompletedLegacyMigrationReceiptRejectsLifecycleAndIdentityChanges(t *testing.T) {
	binding := Record{"scope": "user", "status": "active", "counterSource": "authenticated-client", "identityHash": "endpoint", "userHash": "user", "operationId": "operation", "legacyMigrationToken": strings.Repeat("a", 64)}
	binding["legacyMigrationGeneration"] = config.BindingToken("clash", binding)
	if !completedLegacyMigration("clash", binding, strings.Repeat("a", 64)) {
		t.Fatal("valid receipt rejected")
	}
	for _, patch := range []Record{{"monthlyPaused": true}, {"monthlyBaselinePending": true}, {"status": "revoked"}, {"inboundDeletePending": Record{}}, {"userHash": "other"}, {"identityHash": "changed"}, {"operationId": "new"}, {"counterSource": "inbound"}} {
		changed := clone(binding)
		for key, value := range patch {
			changed[key] = value
		}
		if completedLegacyMigration("clash", changed, strings.Repeat("a", 64)) {
			t.Fatal("changed binding accepted", patch)
		}
	}
	if completedLegacyMigration("other", binding, strings.Repeat("a", 64)) {
		t.Fatal("receipt crossed profiles")
	}
}
