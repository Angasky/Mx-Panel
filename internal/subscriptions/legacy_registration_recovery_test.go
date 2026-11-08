package subscriptions

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

// Models a remote write that succeeded before its local metadata was saved.
// Reads cannot reconcile that gap; only re-entering enrollment can do so.
type interruptedLegacyRegistration struct {
	*legacyCoreMigrationBackend
	pending bool
	reads   int
}

func (b *interruptedLegacyRegistration) SubscriptionUser(ctx context.Context, server string, binding Record, operation string, user Record) (Record, error) {
	b.reads++
	if b.pending {
		return nil, errors.New("remote and managed configuration disagree")
	}
	return b.fakeBackend.SubscriptionUser(ctx, server, binding, operation, user)
}
func (b *interruptedLegacyRegistration) EnrollLegacyCoreUser(ctx context.Context, server string, binding Record) (Record, error) {
	b.enrolls++
	if b.enrolls == 1 {
		b.pending = true
		return nil, errors.New("SSH disconnected after registration write")
	}
	b.pending = false
	return b.fakeBackend.SubscriptionUser(ctx, server, binding, "read", nil)
}

func TestLegacyRegistrationRecoversAfterRemoteWriteAndRestart(t *testing.T) {
	c, base, root := controllerFixture(t)
	row := base.rows[0]
	user := Record{"email": "legacy-recovery", "auth": "original-secret", "enable": true}
	row["settings"].(Record)["clients"] = []any{user}
	server, _ := base.Record("s")
	nodes, err := remote.InboundNodes(row, server)
	if err != nil || len(nodes) != 1 {
		t.Fatal(err)
	}
	if err := c.Repository.Mutate("clash", func(doc Record) error { doc["proxies"] = []any{nodes[0]}; return nil }); err != nil {
		t.Fatal(err)
	}
	hash, err := remote.LegacyInboundIdentity(row)
	if err != nil {
		t.Fatal(err)
	}
	binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active", "identityHash": hash, "counterSource": "inbound", "up": 20, "down": 0}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{binding}
		p["traffic"] = Record{"upload": 7, "enabled": true, "enforce": true}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	base.stats["legacy-recovery"] = Record{"up": int64(40), "down": int64(3), "source": "authenticated-client"}
	backend := &interruptedLegacyRegistration{legacyCoreMigrationBackend: &legacyCoreMigrationBackend{fakeBackend: base}}
	c.Backend = backend
	token := config.BindingToken("clash", stateBinding(t, c))
	before, _ := c.Repository.State("clash")
	yaml, _ := c.Repository.Raw("clash")
	if _, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err == nil || !backend.pending {
		t.Fatal("interruption reported success")
	}
	after, _ := c.Repository.State("clash")
	if !reflect.DeepEqual(before, after) {
		t.Fatal("failed registration changed billing or ownership")
	}
	restarted := New(&config.Repository{Root: root}, backend)
	result, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, token, true)
	if err != nil || result["migrated"] != true || backend.pending || backend.enrolls != 2 || backend.reads != 0 {
		t.Fatal("registration recovery blocked by ordinary read", result, err)
	}
	current, _ := restarted.Repository.State("clash")
	migrated := stateBinding(t, restarted)
	if migrated["scope"] != "user" || text(migrated["up"]) != "40" || text(traffic(current)["upload"]) != "7" || base.adds != 0 {
		t.Fatal("recovery charged history or replaced user")
	}
	if got, _ := restarted.Repository.Raw("clash"); got != yaml {
		t.Fatal("recovery rewrote connection")
	}
	if _, err := restarted.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err != nil || backend.enrolls != 2 {
		t.Fatal("completed replay registered again", err)
	}
}
