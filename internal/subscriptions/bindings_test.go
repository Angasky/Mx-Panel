package subscriptions

import (
	"context"
	"errors"
	"testing"
	"time"

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

func TestHistoryCleanupReportsRetainedRecoveryRecords(t *testing.T) {
	c, base, _ := controllerFixture(t)
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{Record{"status": "missing", "localCleanupPending": true}, Record{"status": "revoked", "inboundDeletePending": Record{}}, Record{"status": "missing"}, Record{"status": "active", "inboundDeletePending": Record{}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	result, err := c.CleanupBindings(context.Background(), "clash", true)
	if err != nil || result["removed"] != 1 || result["retainedPending"] != 2 {
		t.Fatal(result, err)
	}
	if len(base.ops) != 0 {
		t.Fatal("history cleanup called remote backend")
	}
}

func TestForgetServerWaitsForCreationBeforeFirstBindingExists(t *testing.T) {
	c, b, _ := controllerFixture(t)
	manager := b.sealer
	record, err := manager.Save(Record{"name": "pending", "host": "192.0.2.1", "sshPassword": "test-password", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "panelPassword": "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	id := text(record["id"])
	c.Backend = manager
	release, err := c.lockServer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	if _, err = c.ForgetServer(ctx, id, true); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("forget bypassed in-flight creation without binding", err)
	}
	if _, err = manager.Record(id); err != nil {
		t.Fatal("server removed during pending creation", err)
	}
}

func TestServerIdentitySaveSerializesBeforeFirstOwnership(t *testing.T) {
	c, b, _ := controllerFixture(t)
	manager := b.sealer
	record, err := manager.Save(Record{"name": "original", "host": "192.0.2.1", "sshPassword": "test-password", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "panelPassword": "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	id := text(record["id"])
	c.Backend = manager
	release, err := c.lockServer(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	_, err = c.SaveServer(ctx, Record{"id": id, "host": "192.0.2.2"})
	release()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("identity save bypassed creation", err)
	}
	current, err := manager.Record(id)
	if err != nil || current["host"] != "192.0.2.1" {
		t.Fatal("canceled save changed identity", err)
	}
	if err = c.Repository.UpdateState("clash", func(p Record) error {
		p["remoteNodes"] = []any{Record{"serverId": id, "status": "provisioning"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.SaveServer(context.Background(), Record{"id": id, "host": "192.0.2.2"}); err == nil {
		t.Fatal("new ownership not rechecked")
	}
}
