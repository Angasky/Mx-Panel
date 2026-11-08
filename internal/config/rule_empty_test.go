package config

import (
	"os"
	"testing"
)

func TestRuleExplicitEmptyDoesNotBecomeDefault(t *testing.T) {
	r, path, _ := fixture(t)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range []Document{
		{"type": "", "value": "example.com"},
		{"type": "  ", "value": "example.com"},
		{"action": "", "value": "example.com"},
		{"action": " \t", "value": "example.com"},
		{"type": "MATCH", "action": ""},
	} {
		if err := r.Mutate("clash", func(d Document) error { return EditRule(d, "POST", payload) }); err == nil {
			t.Fatalf("accepted empty field: %#v", payload)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(before) {
			t.Fatal("rejected edit changed file", err)
		}
	}
	if err := r.Mutate("clash", func(d Document) error { return EditRule(d, "POST", Document{"value": "example.com"}) }); err != nil {
		t.Fatal(err)
	}
	d, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	if d["rules"].([]any)[0].(map[string]any)["raw"] != "DOMAIN-SUFFIX,example.com,DIRECT" {
		t.Fatal(d["rules"])
	}
	raw, err := buildRule(Document{"value": "example.com"})
	if err != nil || raw != "DOMAIN-SUFFIX,example.com,DIRECT" {
		t.Fatal(raw, err)
	}
}

func TestGroupRulesRejectCommaOnlyMatch(t *testing.T) {
	for _, value := range []string{"DOMAIN-SUFFIX,", "DOMAIN-SUFFIX,,,", "DOMAIN-SUFFIX, , , "} {
		if _, err := scopedGroupRule(value, "Media"); err == nil {
			t.Fatalf("accepted empty match: %q", value)
		}
	}
	raw, err := scopedGroupRule("AND,((NETWORK,TCP),(DST-PORT,443))", "Media")
	if err != nil || raw != "AND,((NETWORK,TCP),(DST-PORT,443)),Media" {
		t.Fatal(raw, err)
	}
}
