package remote

import (
	"reflect"
	"testing"
)

func TestPatchCoreInboundPreservesUnrelatedConfiguration(t *testing.T) {
	managed := Record{"tag": "mxioc-inbound-17"}
	manual := Record{"tag": "manual", "port": 443}
	doc := Record{"inbounds": []any{managed, manual}, "routing": Record{"rules": []any{}}}
	updated := Record{"tag": "manual", "port": 444}
	for _, operation := range []struct {
		verb, tag string
		inbound   Record
	}{
		{"update", "mxioc-inbound-17", managed},
		{"update", "manual", Record{"tag": "other"}},
		{"create", "manual", updated},
		{"update", "missing", Record{"tag": "missing"}},
	} {
		if _, err := patchCoreInbound(doc, operation.verb, operation.tag, operation.inbound); err == nil {
			t.Errorf("unexpected success: %v", operation)
		}
	}
	newInbound := Record{"tag": "new", "port": 445}
	if _, err := patchCoreInbound(doc, "create", "new", newInbound); err != nil {
		t.Fatal(err)
	}
	if _, err := patchCoreInbound(doc, "update", "manual", updated); err != nil {
		t.Fatal(err)
	}
	want := Record{"inbounds": []any{managed, updated, newInbound}, "routing": Record{"rules": []any{}}}
	if !reflect.DeepEqual(doc, want) {
		t.Fatalf("unexpected configuration: %v", doc)
	}
}

func TestDeleteCoreInboundRejectsReferences(t *testing.T) {
	target := Record{"tag": "entry", "port": 443}
	other := Record{"tag": "other", "port": 444}
	for _, rule := range []struct {
		key, field string
	}{
		{"routing", "inboundTag"},
		{"route", "inbound"},
	} {
		doc := Record{"inbounds": []any{target, other}, rule.key: Record{
			"rules": []any{Record{rule.field: []any{"entry"}}},
		}}
		if _, err := patchCoreInbound(doc, "delete", "entry", nil); err == nil {
			t.Errorf("accepted deletion with %s reference", rule.key)
		}
		if !reflect.DeepEqual(doc["inbounds"], []any{target, other}) {
			t.Fatal("rejected deletion mutated the input")
		}
		delete(doc, rule.key)
		next, err := patchCoreInbound(doc, "delete", "entry", nil)
		if err != nil || !reflect.DeepEqual(next["inbounds"], []any{other}) {
			t.Fatalf("delete: %v, %v", next, err)
		}
	}
}
