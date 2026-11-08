package subscriptions

import (
	"context"
	"strings"
	"testing"
)

func TestRawPanelCreateDoesNotProvisionOrBindSubscription(t *testing.T) {
	c, base, _ := controllerFixture(t)
	backend := &templateBackend{fakeBackend: base, created: map[string]int{}}
	c.Backend = backend
	if err := c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["expire"] = c.Now().Unix() - 1; return nil }); err != nil {
		t.Fatal(err)
	}
	before, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	// Raw creation is administrative; expiry of the selected subscription does
	// not grant its users access, nor prevent managing unrelated panel inbounds.
	payload := Record{"operationId": strings.Repeat("a", 32), "inbound": Record{"port": 24001, "protocol": "vmess"}}
	for i := 0; i < 2; i++ {
		result, err := c.CreateInbound(context.Background(), "clash", "s", payload)
		if err != nil || result["bound"] != false || result["enforcementEnabled"] != false {
			t.Fatal(result, err)
		}
	}
	after, _ := c.Repository.State("clash")
	if backend.creates != 1 || backend.adds != 0 || text(before["updatedAt"]) != text(after["updatedAt"]) {
		t.Fatal("raw operation provisioned or changed subscription")
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("raw operation imported nodes")
	}
	payload["inbound"] = nil
	if _, err := c.CreateInbound(context.Background(), "clash", "s", payload); err == nil || backend.creates != 1 {
		t.Fatal("invalid input reached backend")
	}
}
