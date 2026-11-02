package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestRuleGroupDNSAndRawTransactions(t *testing.T) {
	r, _, _ := fixture(t)
	mutate := func(fn func(Document) error) {
		t.Helper()
		if err := r.Mutate("clash", fn); err != nil {
			t.Fatal(err)
		}
	}
	mutate(func(doc Document) error {
		return EditGroup(doc, "POST", map[string]any{"config": map[string]any{"name": "Media", "type": "select", "proxies": []any{"DIRECT"}, "custom": "preserve"}})
	})
	mutate(func(doc Document) error {
		return EditRule(doc, "POST", map[string]any{"type": "IP-CIDR", "value": "192.0.2.0/24", "action": "Media", "options": "no-resolve"})
	})
	mutate(func(doc Document) error {
		return EditGroup(doc, "PUT", map[string]any{"oldName": "Media", "config": map[string]any{"name": "Video", "type": "select", "proxies": []any{"DIRECT"}}})
	})
	got, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	rule := got["rules"].([]any)[0].(map[string]any)
	if rule["action"] != "Video" || rule["value"] != "192.0.2.0/24" || rule["options"] != "no-resolve" {
		t.Fatal("rule contract or rename broken", rule)
	}
	mutate(func(doc Document) error {
		return EditDNS(doc, "POST", map[string]any{"domain": "+.example.com", "servers": "https://dns.google/dns-query\n1.1.1.1"})
	})
	got, err = r.Snapshot("clash")
	if err != nil || len(got["dnsPolicies"].([]any)) != 1 {
		t.Fatal("DNS snapshot missing")
	}
	before, _ := r.Raw("clash")
	err = r.Mutate("clash", func(doc Document) error {
		return ReplaceRaw(doc, map[string]any{"yaml": "proxies: []\n---\npassword: invalid"})
	})
	after, _ := r.Raw("clash")
	if err == nil || before != after {
		t.Fatal("multiple YAML documents accepted or rejected write persisted")
	}
	mutate(func(doc Document) error { return EditGroup(doc, "DELETE", map[string]any{"name": "Video"}) })
	got, err = r.Snapshot("clash")
	if err != nil || len(got["rules"].([]any)) != 0 {
		t.Fatal("deleted group left routing references")
	}
}
func TestRejectGroupCycleAndProtectedComponents(t *testing.T) {
	r, primary, mirror := fixture(t)
	err := r.Mutate("clash", func(doc Document) error {
		doc["proxy-groups"] = []any{map[string]any{"name": "A", "type": "select", "proxies": []any{"B"}}}
		return EditGroup(doc, "POST", map[string]any{"config": map[string]any{"name": "B", "type": "select", "proxies": []any{"A"}}})
	})
	if err == nil {
		t.Fatal("group cycle accepted")
	}
	// Use a profile owning a failover component; even raw editing must preserve it.
	if err = r.Mutate("clash", func(doc Document) error { return EditNode(doc, "POST", map[string]any{"config": node("owned")}) }); err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(map[string]any{"profiles": []any{map[string]any{"id": "clash", "files": []string{primary, mirror}, "failovers": []any{map[string]any{"name": "HA", "entries": []string{"owned"}}}}}})
	if err = os.WriteFile(filepath.Join(r.Root, "profiles.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	before, _ := r.Raw("clash")
	err = r.Mutate("clash", func(doc Document) error { return EditNode(doc, "DELETE", map[string]any{"name": "owned"}) })
	after, _ := r.Raw("clash")
	if err == nil || before != after {
		t.Fatal("protected failover component changed")
	}
}
