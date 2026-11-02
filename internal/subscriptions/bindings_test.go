package subscriptions

import (
	"context"
	"errors"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func TestBindingRemovalSerializesWithCollectors(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "server", []int{1}); err != nil {
		t.Fatal(err)
	}
	binding := stateBinding(t, c)
	token := config.BindingToken("clash", binding)
	release, err := c.lock(context.Background(), "clash")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.RemoveBinding(ctx, "clash", 0, token, true); !errors.Is(err, context.Canceled) {
		t.Fatal("removal bypassed collector", err)
	}
	if _, err = c.CleanupBindings(ctx, "clash", true); !errors.Is(err, context.Canceled) {
		t.Fatal("cleanup bypassed collector", err)
	}
	p, _ := c.Repository.State("clash")
	if len(objects(p["remoteNodes"])) != 1 {
		t.Fatal("canceled removal changed ownership")
	}
	release()
	if _, err = c.RemoveBinding(context.Background(), "clash", 0, token, true); err != nil {
		t.Fatal(err)
	}
	// Deleting local ownership deliberately leaves the remote user untouched.
	if len(b.rows[0]["settings"].(Record)["clients"].([]any)) != 1 {
		t.Fatal("local removal revoked user")
	}
}

func TestForgetServerSerializesWithPendingCreation(t *testing.T) {
	c, b, _ := controllerFixture(t)
	m := b.sealer
	server, err := m.Save(Record{"name": "offline", "host": "192.0.2.1", "sshPassword": "test-password", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "panelPassword": "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	id := text(server["id"])
	if err = c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{Record{"serverId": id, "status": "provisioning", "operationId": "pending", "pendingUser": "cipher"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	c.Backend = m
	release, err := c.lock(context.Background(), "clash")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = c.ForgetServer(ctx, id, true); !errors.Is(err, context.Canceled) {
		t.Fatal("forgot pending creation while locked", err)
	}
	if _, err = m.Record(id); err != nil {
		t.Fatal("canceled deletion removed registry")
	}
	release()
	result, err := c.ForgetServer(context.Background(), id, true)
	if err != nil || result["detachedBindings"] != 1 {
		t.Fatal(result, err)
	}
	if stateBinding(t, c)["status"] != "detached" {
		t.Fatal("pending ownership not detached")
	}
}
