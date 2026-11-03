package config

import "testing"

func TestCountryFlagsUpdateReferencesAndPreserveConfiguration(t *testing.T) {
	r, _, _ := fixture(t)
	if err := r.Mutate("clash", func(d Document) error {
		d["proxies"] = []any{node("A"), node("B")}
		d["proxy-groups"] = []any{Document{"name": "Proxy", "type": "select", "proxies": []any{"A", "B"}}}
		d["rules"] = []any{"MATCH,A"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	targets, err := r.FlagTargets("clash", []any{"A"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := r.ApplyCountryFlags("clash", targets, map[string]FlagCountry{"vpn.example.com": {Code: "US", IP: "8.8.8.8"}})
	if err != nil || result["updated"] != 1 {
		t.Fatal(result, err)
	}
	snapshot, _ := r.Snapshot("clash")
	nodes := snapshot["nodes"].([]any)
	if nodes[0].(Document)["name"] != "🇺🇸 A" || nodes[0].(Document)["config"].(Document)["password"] != "secret" {
		t.Fatal("rename lost node fields")
	}
	if snapshot["rules"].([]any)[0].(Document)["action"] != "🇺🇸 A" {
		t.Fatal("rule action not renamed")
	}
	targets, _ = r.FlagTargets("clash", []any{"🇺🇸 A"})
	result, err = r.ApplyCountryFlags("clash", targets, map[string]FlagCountry{"vpn.example.com": {Code: "US"}})
	if err != nil || result["unchanged"] != 1 {
		t.Fatal(result, err)
	}
}
func TestCountryFlagsRejectStaleIdentitiesConflictsAndProtectedNodes(t *testing.T) {
	r, _, _ := fixture(t)
	r.Mutate("clash", func(d Document) error { d["proxies"] = []any{node("A"), node("🇺🇸 A")}; return nil })
	targets, _ := r.FlagTargets("clash", []any{"A"})
	result, err := r.ApplyCountryFlags("clash", targets, map[string]FlagCountry{"vpn.example.com": {Code: "US"}})
	if err != nil || result["updated"] != 0 || len(result["skipped"].([]any)) != 1 {
		t.Fatal("name conflict not skipped", result, err)
	}
	r.Mutate("clash", func(d Document) error { d["proxies"].([]any)[0].(Document)["password"] = "new-identity"; return nil })
	result, err = r.ApplyCountryFlags("clash", targets, map[string]FlagCountry{"vpn.example.com": {Code: "JP"}})
	if err != nil || result["updated"] != 0 {
		t.Fatal("stale identity renamed", result, err)
	}
	r.UpdateState("clash", func(p Document) error { p["failovers"] = []any{Document{"paths": []any{"A"}}}; return nil })
	if _, err = r.FlagTargets("clash", []any{"A"}); err == nil {
		t.Fatal("protected path selected")
	}
}
