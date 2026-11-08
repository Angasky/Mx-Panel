package config

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestNodeOrderPreservesManagedFailoverPriority(t *testing.T) {
	r, _, _ := fixture(t)
	if err := r.Mutate("clash", func(d Document) error {
		d["proxies"] = []any{node("A"), node("B"), node("C")}
		d["proxy-groups"] = []any{
			Document{"name": "HA", "type": "fallback", "proxies": []any{"A", "B"}},
			Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT", "A", "HA", "B", "C"}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateState("clash", func(p Document) error {
		p["failovers"] = []any{Document{"name": "HA", "paths": []any{"A", "B"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.MoveNode("clash", Document{"name": "B", "targetName": "A"}); err != nil {
		t.Fatal("Python default before failed", err)
	}
	snapshot, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	groups := snapshot["groups"].([]any)
	for _, raw := range groups {
		g := raw.(Document)["config"].(Document)
		want := []any{"A", "B"}
		if g["name"] == "Proxy" {
			want = []any{"DIRECT", "B", "HA", "A", "C"}
		}
		if !reflect.DeepEqual(g["proxies"], want) {
			t.Fatal("group ordering", g)
		}
	}
	if err := r.Mutate("clash", func(d Document) error {
		rows(d, "proxy-groups")[0].(Document)["proxies"] = []any{"B", "A"}
		return nil
	}); err == nil {
		t.Fatal("direct priority change bypassed protection")
	}
}

func TestDNSMalformedStateIsNotOverwritten(t *testing.T) {
	for _, doc := range []Document{
		{"dns": nil}, {"dns": "preserve"}, {"dns": []any{"preserve"}},
		{"dns": Document{"nameserver-policy": nil, "enable": true}},
		{"dns": Document{"nameserver-policy": []any{"preserve"}}},
	} {
		before, _ := json.Marshal(doc)
		if err := EditDNS(doc, "POST", Document{"domain": "example.com", "servers": []any{"1.1.1.1"}}); err == nil {
			t.Fatal("malformed DNS replaced")
		}
		after, _ := json.Marshal(doc)
		if string(before) != string(after) {
			t.Fatal("failed DNS edit changed input")
		}
	}
}

func TestAddingNodeOnlyJoinsOrdinarySelectGroups(t *testing.T) {
	doc := Document{"proxies": []any{}, "proxy-groups": []any{
		Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}},
		Document{"name": "HA", "type": "fallback", "proxies": []any{"DIRECT"}},
		Document{"name": "Latency", "type": "url-test", "proxies": []any{"DIRECT"}},
		Document{"name": "🛑 广告拦截", "type": "select", "proxies": []any{"REJECT"}},
	}}
	if err := EditNode(doc, "POST", Document{"config": node("A"), "addToGroups": true}); err != nil {
		t.Fatal(err)
	}
	for _, v := range rows(doc, "proxy-groups") {
		group := v.(Document)
		refs := group["proxies"].([]any)
		if group["name"] == "Proxy" {
			if !reflect.DeepEqual(refs, []any{"DIRECT", "A"}) {
				t.Fatal(refs)
			}
		} else if len(refs) != 1 {
			t.Fatal("automatic insertion changed special group", group)
		}
	}
}

func TestNodeOrderPreservesProviderOnlyGroup(t *testing.T) {
	doc := Document{
		"proxies":      []any{node("A"), node("B")},
		"proxy-groups": []any{Document{"name": "Remote", "type": "select", "use": []any{"provider"}}},
	}
	group := rows(doc, "proxy-groups")[0].(Document)
	before, _ := json.Marshal(group)
	if err := MoveNode(doc, Document{"name": "B", "targetName": "A"}); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(group)
	if string(before) != string(after) {
		t.Fatalf("provider-only group changed: %s -> %s", before, after)
	}
	if rows(doc, "proxies")[0].(Document)["name"] != "B" {
		t.Fatal("nodes did not move")
	}
}
