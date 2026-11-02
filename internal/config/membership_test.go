package config

import "testing"

func TestMembershipPreservesOrderAndRejectsEmpty(t *testing.T) {
	doc := Document{"proxies": []any{node("A"), node("B")}, "proxy-groups": []any{
		map[string]any{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT", "A", "B"}},
		map[string]any{"name": "Media", "type": "select", "proxies": []any{"DIRECT"}},
		map[string]any{"name": "protected", "type": "select", "proxies": []any{"A"}},
	}}
	if err := EditMembership(doc, map[string]any{"name": "A", "groups": []any{"Media"}}, []string{"Proxy", "Media"}); err != nil {
		t.Fatal(err)
	}
	groups := rows(doc, "proxy-groups")
	refs := groups[0].(map[string]any)["proxies"].([]any)
	if len(refs) != 2 || refs[0] != "DIRECT" || refs[1] != "B" {
		t.Fatal("existing order changed")
	}
	if groups[1].(map[string]any)["proxies"].([]any)[1] != "A" {
		t.Fatal("new member not appended")
	}
	if groups[2].(map[string]any)["proxies"].([]any)[0] != "A" {
		t.Fatal("protected group changed")
	}
	if err := EditMembership(doc, map[string]any{"name": "A", "groups": []any{}}, []string{"protected"}); err == nil {
		t.Fatal("empty group allowed")
	}
}
