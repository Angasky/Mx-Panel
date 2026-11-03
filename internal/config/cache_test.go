package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestCacheIsolationAndExternalRewrite(t *testing.T) {
	r, primary, _ := fixture(t)
	if err := r.Mutate("clash", func(doc Document) error { doc["proxies"] = []any{node("A")}; return nil }); err != nil {
		t.Fatal(err)
	}
	wire, err := r.SnapshotJSON("clash")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	snapshot["nodes"].([]any)[0].(Document)["config"].(Document)["password"] = "poison"
	wire[0] = '!'
	source, err := r.ConversionSource("clash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	source.Document["proxies"].([]any)[0].(Document)["password"] = "poison"
	source.Raw[0] = '!'
	after, err := r.SnapshotJSON("clash")
	if err != nil || bytes.Contains(after, []byte("poison")) || !json.Valid(after) {
		t.Fatal("cache leaked mutable references", err)
	}
	// A same-size rewrite with restored mtime must still invalidate JSON and YAML.
	original, _ := os.ReadFile(primary)
	info, _ := os.Stat(primary)
	changed := bytes.Replace(original, []byte("secret"), []byte("newkey"), 1)
	if bytes.Equal(original, changed) {
		t.Fatal("bad fixture")
	}
	if err = os.WriteFile(primary, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chtimes(primary, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	after, err = r.SnapshotJSON("clash")
	if err != nil || !bytes.Contains(after, []byte("newkey")) {
		t.Fatal("external edit served stale snapshot", err)
	}
	if err = os.WriteFile(primary, []byte("proxies: [broken"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = r.SnapshotJSON("clash"); err == nil {
		t.Fatal("served cached data after invalid external edit")
	}
	if err = os.Remove(primary); err != nil {
		t.Fatal(err)
	}
	if _, err = r.Raw("clash"); err == nil {
		t.Fatal("served deleted config")
	}
}

func TestNoopSavePreservesBytesButRepairsMirrors(t *testing.T) {
	r, primary, mirror := fixture(t)
	raw, _ := os.ReadFile(primary)
	raw = append([]byte("# retain comments\n"), raw...)
	for _, path := range []string{primary, mirror} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	stamp := time.Unix(1700000000, 0)
	if err := os.Chtimes(primary, stamp, stamp); err != nil {
		t.Fatal(err)
	}
	noop := func(Document) error { return nil }
	if err := r.Mutate("clash", noop); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(primary)
	backups, _ := r.Backups("clash")
	if !info.ModTime().Equal(stamp) || len(backups) != 0 {
		t.Fatal("noop touched disk")
	}
	for _, missing := range []bool{false, true} {
		if missing {
			if err := os.Remove(mirror); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.WriteFile(mirror, []byte("diverged"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Mutate("clash", noop); err != nil {
			t.Fatal(err)
		}
		a, _ := os.ReadFile(primary)
		b, _ := os.ReadFile(mirror)
		if !bytes.Equal(a, raw) || !bytes.Equal(b, raw) {
			t.Fatal("noop repair lost primary comments or mirror")
		}
	}
	// Callback error after modifying a private working copy must not poison cache.
	if err := r.Mutate("clash", func(d Document) error { d["proxies"] = []any{node("poison")}; return errors.New("reject") }); err == nil {
		t.Fatal("callback failure ignored")
	}
	snapshot, _ := r.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("rejected edit poisoned cache")
	}
}

func TestCacheMetadataAndTokenRemainFresh(t *testing.T) {
	r, _, _ := fixture(t)
	slug := strings.Repeat("a", 50)
	if err := r.UpdateState("clash", func(p Document) error {
		p["slug"] = slug
		p["traffic"] = Document{"enabled": true, "enforce": true, "upload": int64(0), "download": int64(0), "total": int64(100)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, err := r.SnapshotJSON("clash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = r.PublicSubscription(slug, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err = r.UpdateState("clash", func(p Document) error {
		p["name"] = "fresh-name"
		p["traffic"].(Document)["upload"] = int64(100)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	after, err := r.SnapshotJSON("clash")
	if err != nil || bytes.Equal(before, after) || !bytes.Contains(after, []byte("fresh-name")) {
		t.Fatal("metadata was cached", err)
	}
	if _, err = r.PublicSubscription(slug, time.Now()); !errors.Is(err, ErrSubscriptionBlocked) {
		t.Fatal("cached config bypassed quota", err)
	}
	newSlug := strings.Repeat("b", 50)
	if err = r.UpdateState("clash", func(p Document) error { p["slug"] = newSlug; return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PublicSubscription(slug, time.Now()); !errors.Is(err, ErrSubscriptionMissing) {
		t.Fatal("old token still authorizes", err)
	}
}

func TestCacheLRUBoundsAndSnapshotContract(t *testing.T) {
	r, primary, _ := fixture(t)
	wire, err := r.SnapshotJSON("clash")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(snapshot)
	var a, b any
	json.Unmarshal(wire, &a)
	json.Unmarshal(want, &b)
	if !reflect.DeepEqual(a, b) {
		t.Fatal("snapshot wire contract changed")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	raw, _ := os.ReadFile(primary)
	for i := 0; i < configCacheEntries+4; i++ {
		path := filepath.Join(r.Root, fmt.Sprintf("cache-%d.yaml", i))
		if err = os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err = r.cachedEntry(Profile{Files: []string{path}}); err != nil {
			t.Fatal(err)
		}
	}
	if len(r.cache) != configCacheEntries || r.cacheBytes > configCacheBudget || r.cache[primary] != nil {
		t.Fatal("cache exceeded bound or did not evict LRU")
	}
	large := filepath.Join(r.Root, "large.yaml")
	if err = os.WriteFile(large, append(raw, []byte("#"+strings.Repeat("x", configCacheBudget/8))...), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = r.cachedEntry(Profile{Files: []string{large}}); err != nil {
		t.Fatal(err)
	}
	if r.cache[large] != nil {
		t.Fatal("oversized config admitted to cache")
	}
}

func TestJSONNodeNoopAndExactIntegerComparison(t *testing.T) {
	r, primary, _ := fixture(t)
	if err := r.Mutate("clash", func(d Document) error { d["proxies"] = []any{node("A")}; return nil }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(primary)
	backups, _ := r.Backups("clash")
	var payload Document
	decoder := json.NewDecoder(strings.NewReader(`{"oldName":"A","config":{"name":"A","type":"hysteria2","server":"vpn.example.com","port":24443,"password":"secret"}}`))
	decoder.UseNumber()
	if err := decoder.Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if err := r.Mutate("clash", func(d Document) error { return EditNode(d, "PUT", payload) }); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(primary)
	later, _ := r.Backups("clash")
	if !before.ModTime().Equal(after.ModTime()) || len(backups) != len(later) {
		t.Fatal("JSON int64 versus YAML int caused no-op write")
	}
	if !equalConfig(int(9007199254740993), int64(9007199254740993)) || equalConfig(int64(9007199254740993), int64(9007199254740992)) || equalConfig(int64(-1), uint64(^uint64(0))) || equalConfig(1, 1.0) {
		t.Fatal("integer comparison lost precision or types")
	}
}

func TestCommittedCacheIsIndependentAndMatchesDisk(t *testing.T) {
	r, primary, _ := fixture(t)
	var retained Document
	input := node("A")
	if err := r.Mutate("clash", func(doc Document) error {
		retained = doc
		doc["proxies"] = []any{input}
		doc["extra"] = Document{"small": uint64(13), "big": uint64(^uint64(0)), "signed": int64(9007199254740993), "text": "true: #中文\nnext", "nil": nil, "empty": []any{}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	entry := r.cache[primary]
	if entry == nil {
		t.Fatal("successful commit did not warm cache")
	}
	raw, _ := os.ReadFile(primary)
	parsed, _, err := parseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(entry.doc, parsed) {
		t.Fatal("committed document differs from parsed durable YAML")
	}
	input["password"] = "poison"
	retained["extra"].(Document)["small"] = "poison"
	wire, err := r.SnapshotJSON("clash")
	if err != nil || bytes.Contains(wire, []byte("poison")) {
		t.Fatal("callback aliases poisoned commit cache", err)
	}
	if r.cache[primary] != entry {
		t.Fatal("read reparsed a warm committed cache")
	}
}

func TestCommittedCacheFallsBackForNoncanonicalTypes(t *testing.T) {
	r, primary, _ := fixture(t)
	for _, value := range []any{1.0, []string{"A", "B"}, json.Number("13")} {
		if err := r.Mutate("clash", func(doc Document) error { doc["extra"] = value; return nil }); err != nil {
			t.Fatal(err)
		}
		if r.cache[primary] != nil {
			t.Fatal("noncanonical Go value cached without parsing")
		}
		raw, err := r.Raw("clash")
		if err != nil {
			t.Fatal(err)
		}
		parsed, _, err := parseConfig([]byte(raw))
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r.cache[primary].doc, parsed) {
			t.Fatal("fallback parse differs from disk")
		}
	}
}

func TestFailedCommitNeverPublishesWarmCache(t *testing.T) {
	r, primary, _ := fixture(t)
	if _, err := r.SnapshotJSON("clash"); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(primary)
	index, _ := json.Marshal(Document{"profiles": []any{Document{"id": "clash", "files": []string{primary, filepath.Join(r.Root, "absent", "mirror.yaml")}}}})
	if err := os.WriteFile(filepath.Join(r.Root, "profiles.json"), index, 0600); err != nil {
		t.Fatal(err)
	}
	if err := r.Mutate("clash", func(d Document) error { d["proxies"] = []any{node("failed")}; return nil }); err == nil {
		t.Fatal("mirror failure ignored")
	}
	if r.cache[primary] != nil {
		t.Fatal("failed transaction published cache")
	}
	after, _ := r.Raw("clash")
	if string(before) != after {
		t.Fatal("rollback returned attempted config")
	}
}
