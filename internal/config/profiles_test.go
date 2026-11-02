package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileCRUDAndCopyIsolation(t *testing.T) {
	r, _, _ := fixture(t)
	index, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	index["futureField"] = json.Number("9007199254740993")
	if err = r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	created, err := r.CreateProfile(map[string]any{"name": "new profile", "templateId": "blank"})
	if err != nil {
		t.Fatal(err)
	}
	id := created["id"].(string)
	slug := created["slug"].(string)
	if len(slug) != 50 {
		t.Fatal("weak or incorrect slug")
	}
	if err = r.Mutate(id, func(doc Document) error { return EditNode(doc, "POST", map[string]any{"config": node("original")}) }); err != nil {
		t.Fatal(err)
	}
	copied, err := r.CreateProfile(map[string]any{"name": "copy", "templateId": id})
	if err != nil {
		t.Fatal(err)
	}
	copiedID := copied["id"].(string)
	if copied["slug"] == created["slug"] {
		t.Fatal("copied subscription reused token")
	}
	if err = r.Mutate(copiedID, func(doc Document) error { return EditNode(doc, "DELETE", map[string]any{"name": "original"}) }); err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Snapshot(id)
	if err != nil || len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("copy mutation changed original")
	}
	updated, err := r.UpdateProfile(map[string]any{"oldId": id, "name": "renamed", "customSlug": true, "slug": "12345678901234567890123456789012"})
	if err != nil || updated["name"] != "renamed" {
		t.Fatal(err)
	}
	if err = r.DeleteProfile(copiedID); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Snapshot(copiedID); err == nil {
		t.Fatal("deleted subscription still selected")
	}
	if _, err = os.Stat(filepath.Join(r.Root, "profiles", copiedID+".yaml")); !os.IsNotExist(err) {
		t.Fatal("generated file not cleaned up")
	}
	index, err = r.index()
	if err != nil || index["futureField"].(json.Number).String() != "9007199254740993" {
		t.Fatal("unknown index fields or numeric precision lost")
	}
}
func TestOwnedProfileCannotBeCopiedOrDeleted(t *testing.T) {
	r, _, _ := fixture(t)
	index, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	record := index["profiles"].([]any)[0].(map[string]any)
	record["remoteNodes"] = []any{map[string]any{"status": "active", "scope": "user"}}
	if err = r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	if _, err = r.CreateProfile(map[string]any{"name": "copy", "templateId": "clash"}); err == nil {
		t.Fatal("owned credentials copied")
	}
	if err = r.DeleteProfile("clash"); err == nil {
		t.Fatal("owned subscription deleted")
	}
}
