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
