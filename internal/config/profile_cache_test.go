package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestProfileCacheIsolationAndExternalChanges(t *testing.T) {
	r, _, _ := fixture(t)
	index, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	row := index["profiles"].([]any)[0].(Document)
	row["name"] = "CacheAlpha"
	row["traffic"] = Document{"upload": json.Number("9007199254740993")}
	row["remoteNodes"] = []any{Document{"serverId": "original"}}
	row["failovers"] = []any{Document{"name": "original"}}
	row["lastEnforcedAt"] = Document{"test": []any{"original"}}
	if err = r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	profiles, err := r.profiles()
	if err != nil {
		t.Fatal(err)
	}
	if profiles[0].Traffic["upload"] != json.Number("9007199254740993") {
		t.Fatal("integer precision lost")
	}
	profiles[0].Name = "poison"
	profiles[0].Files[0] = "poison"
	profiles[0].Traffic["upload"] = 0
	profiles[0].RemoteNodes[0].(Document)["serverId"] = "poison"
	profiles[0].Failovers[0]["name"] = "poison"
	profiles[0].LastEnforcedAt.(Document)["test"].([]any)[0] = "poison"
	if len(profiles[0].Plans) > 0 {
		profiles[0].Plans[0]["name"] = "poison"
	}
	document, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	document["profiles"].([]any)[0].(Document)["name"] = "poison"
	again, err := r.profiles()
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(again)
	if bytes.Contains(raw, []byte("poison")) {
		t.Fatal("mutable cache escaped")
	}
	path := filepath.Join(r.Root, "profiles.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(original, []byte("CacheAlpha"), []byte("CacheBravo"), 1)
	if bytes.Equal(original, changed) {
		t.Fatal("bad fixture")
	}
	if err = os.WriteFile(path, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	again, err = r.profiles()
	if err != nil || again[0].Name != "CacheBravo" {
		t.Fatal("same metadata rewrite missed", err)
	}
	if err = os.WriteFile(path, []byte(`{"profiles": [broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.index(); err == nil {
		t.Fatal("malformed external index accepted")
	}
	if _, err = r.profiles(); err == nil {
		t.Fatal("stale typed cache served")
	}
	if err = os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.profiles(); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err = r.profiles(); err == nil {
		t.Fatal("deleted index served")
	}
}

func TestProfileCacheTypedValidationAndAdmission(t *testing.T) {
	r, _, _ := fixture(t)
	doc, err := r.index()
	if err != nil {
		t.Fatal(err)
	}
	row := doc["profiles"].([]any)[0].(Document)
	row["protected"] = "wrong-type"
	if err = r.writeIndex(doc); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if _, err = r.profiles(); err == nil {
			t.Fatal("typed field validation skipped")
		}
	}
	row["protected"] = true
	doc["extra"] = string(bytes.Repeat([]byte("x"), 1<<20))
	if err = r.writeIndex(doc); err != nil {
		t.Fatal(err)
	}
	if _, err = r.profiles(); err != nil {
		t.Fatal(err)
	}
	if r.profileCache != nil {
		t.Fatal("oversized index retained")
	}
}
