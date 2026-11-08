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

func TestLegacyProfileReadPersistsSafeSlugsAndInvalidatedBindings(t *testing.T) {
	r, _, _ := fixture(t)
	index, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	record := index["profiles"].([]any)[0].(map[string]any)
	record["slug"], record["customSlug"] = "short", true
	record["remoteNodes"] = []any{map[string]any{"status": "active", "error": "远端入站身份已变化，已停止自动删除，避免误删复用 ID 的节点", "invalidatedAt": 123}, map[string]any{"status": "active", "error": "temporary connection error"}}
	if err = r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	if err := r.MigrateLegacyProfiles(); err != nil {
		t.Fatal(err)
	}
	profiles, err := r.Profiles()
	if err != nil {
		t.Fatal(err)
	}
	slug := profiles[0]["slug"].(string)
	if len(slug) != 50 || profiles[0]["customSlug"] != false {
		t.Fatal("legacy slug not upgraded")
	}
	next := &Repository{Root: r.Root}
	index, err = next.index()
	if err != nil {
		t.Fatal(err)
	}
	record = index["profiles"].([]any)[0].(map[string]any)
	bindings := record["remoteNodes"].([]any)
	first := bindings[0].(map[string]any)
	if record["slug"] != slug || first["status"] != "identity_changed" || first["invalidatedAt"].(json.Number).String() != "123" || bindings[1].(map[string]any)["status"] != "active" {
		t.Fatal("migration not durable or altered unrelated binding")
	}
}

func TestMalformedLegacyProfileFilesDoNotPanicOrCreateCopies(t *testing.T) {
	for _, files := range []any{nil, []any{}, []any{""}} {
		r, _, _ := fixture(t)
		index, err := r.index()
		if err != nil {
			t.Fatal(err)
		}
		index["profiles"] = append(index["profiles"].([]any), Document{"id": "broken", "name": "Broken", "files": files})
		if err = r.writeIndex(index); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.CreateProfile(Document{"name": "copy", "templateId": "broken"}); err == nil {
			t.Fatal("copied profile with no file")
		}
		targets, err := r.ImportTargets("server", []int{1})
		if err != nil {
			t.Fatal(err)
		}
		if len(targets) != 2 || targets[1]["error"] == nil {
			t.Fatal("broken import target not reported", targets)
		}
		after, err := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
		if err != nil || string(before) != string(after) {
			t.Fatal("failed copy mutated index", err)
		}
	}
}

func TestMalformedProfileMutationDoesNotPublishFailedChange(t *testing.T) {
	for _, operation := range []string{"update", "delete"} {
		t.Run(operation, func(t *testing.T) {
			r, primary, _ := fixture(t)
			index, err := r.index()
			if err != nil {
				t.Fatal(err)
			}
			index["profiles"].([]any)[0].(Document)["files"] = []any{123}
			if err = r.writeIndex(index); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(r.Root, "profiles.json")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if operation == "update" {
				_, err = r.UpdateProfile(Document{"oldId": "clash", "name": "renamed"})
			} else {
				err = r.DeleteProfile("clash")
			}
			if err == nil {
				t.Fatal("malformed files accepted")
			}
			after, readErr := os.ReadFile(path)
			if readErr != nil || string(before) != string(after) {
				t.Fatal("failed mutation changed index", readErr)
			}
			if _, err = os.Stat(primary); err != nil {
				t.Fatal("failed mutation removed config", err)
			}
		})
	}
}
