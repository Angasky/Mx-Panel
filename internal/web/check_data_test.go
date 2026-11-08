package web

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDataReadsAllProfilesWithoutChangingFiles(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(s.options.Root, "fixture.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckData(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("check changed configuration")
	}
	if err = os.WriteFile(path, []byte("proxies: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckData(); err == nil {
		t.Fatal("invalid subscription accepted")
	}
}

func TestCheckDataKeepsLegacyIndexReadOnlyBeforeStartupMigration(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(s.options.Root, "profiles.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	record := doc["profiles"].([]any)[0].(map[string]any)
	record["slug"], record["customSlug"] = "legacy", true
	raw, _ = json.Marshal(doc)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	s = reopen(t, s)
	if err = s.CheckData(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(raw) {
		t.Fatal("read-only validation migrated index")
	}
	if err = s.repository.MigrateLegacyProfiles(); err != nil {
		t.Fatal(err)
	}
	after, _ = os.ReadFile(path)
	if string(after) == string(raw) {
		t.Fatal("explicit startup migration did not persist")
	}
}

func TestCheckDataRejectsDuplicateProfileIDsWithoutHidingBrokenRecord(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(s.options.Root, "profiles.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	doc["profiles"] = append(doc["profiles"].([]any), map[string]any{"id": "clash", "files": []string{filepath.Join(s.options.Root, "missing.yaml")}})
	raw, _ = json.Marshal(doc)
	if err = os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckData(); err == nil {
		t.Fatal("duplicate ID hid unreadable profile")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(raw) != string(after) {
		t.Fatal("validation rewrote ambiguous index", err)
	}
}
