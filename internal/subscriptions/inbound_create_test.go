package subscriptions

import (
	"context"
	"strings"
	"testing"
)

type templateBackend struct {
	*fakeBackend
	creates int
	created map[string]int
}

func (b *templateBackend) CreateInbound(ctx context.Context, server, profile string, payload Record) (Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := profile + ":" + text(payload["operationId"])
	if id := b.created[key]; id != 0 {
		for _, row := range b.rows {
			if text(row["id"]) == text(id) {
				return Record{"inbound": clone(row), "reused": true}, nil
			}
		}
	}
	b.creates++
	id := len(b.rows) + 1
	row := Record{"id": id, "port": 24000 + id, "protocol": "hysteria", "enable": true, "remark": "created HY2", "settings": Record{"version": 2, "clients": []any{}}, "streamSettings": Record{"security": "tls", "network": "hysteria", "tlsSettings": Record{"serverName": "node.example.com"}}}
	b.rows = append(b.rows, row)
	b.created[key] = id
	return Record{"inbound": clone(row), "reused": false}, nil
}

func TestTemplateCreateImportsOneOwnedUserAndRetryDoesNotDuplicate(t *testing.T) {
	c, base, _ := controllerFixture(t)
	backend := &templateBackend{fakeBackend: base, created: map[string]int{}}
	c.Backend = backend
	payload := Record{"operationId": strings.Repeat("a", 32), "template": "hysteria2"}
	result, err := c.CreateInbound(context.Background(), "clash", "s", payload)
	if err != nil || backend.creates != 1 || backend.adds != 1 || result["bound"] != true || len(result["shareLinks"].([]any)) != 1 {
		t.Fatal(result, err)
	}
	secret := text(backend.rows[3]["settings"].(Record)["clients"].([]any)[0].(Record)["auth"])
	result, err = c.CreateInbound(context.Background(), "clash", "s", payload)
	if err != nil || backend.creates != 1 || backend.adds != 1 || result["existing"] != 1 {
		t.Fatal("retry duplicated", result, err)
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("owned node not saved")
	}
	other, err := c.Repository.CreateProfile(Record{"name": "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.Batch(context.Background(), text(other["id"]), "s", []int{4}); err != nil {
		t.Fatal(err)
	}
	clients := backend.rows[3]["settings"].(Record)["clients"].([]any)
	if len(clients) != 2 || text(clients[1].(Record)["auth"]) == secret {
		t.Fatal("credentials shared across subscriptions")
	}
	if err = c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["expire"] = c.Now().Unix() - 1; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	clients = backend.rows[3]["settings"].(Record)["clients"].([]any)
	if len(clients) != 1 || text(clients[0].(Record)["auth"]) == secret {
		t.Fatal("expiry failed to isolate original user")
	}
	if _, err = c.CreateInbound(context.Background(), "clash", "s", Record{"operationId": strings.Repeat("b", 32)}); err == nil || backend.creates != 1 {
		t.Fatal("expired subscription created inbound")
	}
}

func TestTemplateCreatePendingUserKeepsCredentialAcrossRetry(t *testing.T) {
	c, base, _ := controllerFixture(t)
	backend := &templateBackend{fakeBackend: base, created: map[string]int{}}
	c.Backend = backend
	base.failAfter = true
	payload := Record{"operationId": strings.Repeat("a", 32), "template": "hysteria2"}
	if _, err := c.CreateInbound(context.Background(), "clash", "s", payload); err == nil {
		t.Fatal("ambiguous user creation reported success")
	}
	before := stateBinding(t, c)
	if before["status"] != "provisioning" || text(before["pendingUser"]) == "" {
		t.Fatal("pending identity not durable")
	}
	base.failAfter = false
	result, err := c.CreateInbound(context.Background(), "clash", "s", payload)
	if err != nil || backend.creates != 1 || backend.adds != 1 || result["added"] != 1 {
		t.Fatal("retry duplicated inbound/user", result, err)
	}
	after := stateBinding(t, c)
	if before["userHash"] != after["userHash"] || before["operationId"] != after["operationId"] || after["status"] != "active" {
		t.Fatal("replaced pending credential")
	}
}
