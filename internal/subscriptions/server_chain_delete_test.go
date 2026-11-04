package subscriptions

import (
	"context"
	"testing"
)

type namedRelayBackend struct{ *inboundBackend }

func (b namedRelayBackend) DeleteNamedRelay(ctx context.Context, server string, id int, expected string, guard func(Record) error) (Record, error) {
	return b.DeleteInbound(ctx, server, id, expected, guard)
}

func TestDeleteNamedServerChainPreservesSharedInboundAndRetries(t *testing.T) {
	c, base, _ := controllerFixture(t)
	ctx := context.Background()
	backend := namedRelayBackend{&inboundBackend{fakeBackend: base}}
	c.Backend = backend
	if _, err := c.Batch(ctx, "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	binding := stateBinding(t, c)
	names, _ := binding["importedNames"].([]any)
	if len(names) != 1 {
		t.Fatal("expected one owned node")
	}
	name := text(names[0])
	chain := Record{"name": name, "serverId": "s", "inboundId": 1}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["serverChains"] = []any{chain}
		p["failovers"] = []any{Record{"name": "HA", "paths": []any{name}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteServerChain(ctx, "clash", name); err == nil || backend.writes != 0 {
		t.Fatal("HA path was not protected", err)
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		delete(p, "failovers")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	settings := base.rows[0]["settings"].(Record)
	clients := settings["clients"].([]any)
	settings["clients"] = append(clients, Record{"email": "unrelated", "auth": "fixture-other"})
	if _, err := c.DeleteServerChain(ctx, "clash", name); err == nil || backend.writes != 0 {
		t.Fatal("shared inbound was not protected", err)
	}
	settings["clients"] = clients
	backend.uncertain = true
	if _, err := c.DeleteServerChain(ctx, "clash", name); err == nil || backend.writes != 1 {
		t.Fatal("uncertain remote deletion accepted", err)
	}
	if _, _, err := c.Repository.ServerChainTarget("clash", name); err != nil {
		t.Fatal("uncertain deletion removed metadata", err)
	}
	backend.uncertain = false
	result, err := c.DeleteServerChain(ctx, "clash", name)
	if err != nil || result["removedLocalNodes"] != 1 {
		t.Fatal(result, err)
	}
	if _, _, err := c.Repository.ServerChainTarget("clash", name); err == nil {
		t.Fatal("deleted chain metadata retained")
	}
}
