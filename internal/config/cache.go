package config

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
)

const configCacheEntries = 32
const configCacheBudget = 32 << 20

type configEntry struct {
	digest       [32]byte
	doc          Document
	snapshotJSON []byte
	weight       int
	used         uint64
}

// All cache access is under Repository.mu. Values are immutable: callers that
// expose or edit a document must clone it. Always hash the file contents, rather
// than trusting size/mtime (external tools can preserve both).
func (r *Repository) cachedEntry(p Profile) (*configEntry, []byte, error) {
	path := filepath.Clean(p.Files[0])
	f, err := os.Open(path)
	if err != nil {
		r.invalidateConfig(path)
		return nil, nil, errors.New("订阅配置读取失败")
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	f.Close()
	if err != nil || len(raw) > 8<<20 {
		r.invalidateConfig(path)
		return nil, nil, errors.New("订阅配置超过限制")
	}
	digest := sha256.Sum256(raw)
	r.cacheClock++
	if entry := r.cache[path]; entry != nil && entry.digest == digest {
		entry.used = r.cacheClock
		return entry, raw, nil
	}
	r.invalidateConfig(path)
	doc, _, err := parseConfig(raw)
	if err != nil {
		return nil, nil, err
	}
	entry := &configEntry{digest: digest, doc: doc, weight: len(raw) * 8, used: r.cacheClock}
	// The raw-size multiplier is a conservative admission budget, not an RSS
	// guarantee. Large documents are served uncached; there are at most 32 entries.
	if entry.weight <= configCacheBudget {
		if r.cache == nil {
			r.cache = map[string]*configEntry{}
		}
		for len(r.cache) >= configCacheEntries || r.cacheBytes+entry.weight > configCacheBudget {
			r.evictConfig()
		}
		r.cache[path] = entry
		r.cacheBytes += entry.weight
	}
	return entry, raw, nil
}

func (r *Repository) cachedRead(p Profile) (Document, []byte, error) {
	entry, raw, err := r.cachedEntry(p)
	if err != nil {
		return nil, nil, err
	}
	return entry.doc, raw, nil
}
func (r *Repository) invalidateConfig(path string) {
	path = filepath.Clean(path)
	if old := r.cache[path]; old != nil {
		r.cacheBytes -= old.weight
		delete(r.cache, path)
	}
}
func (r *Repository) evictConfig() {
	var oldest string
	var used uint64 = ^uint64(0)
	for path, entry := range r.cache {
		if entry.used < used {
			oldest = path
			used = entry.used
		}
	}
	r.invalidateConfig(oldest)
}

func cloneConfig(v any) any {
	switch x := v.(type) {
	case map[string]any:
		copy := make(map[string]any, len(x))
		for k, v := range x {
			copy[k] = cloneConfig(v)
		}
		return copy
	case map[any]any:
		copy := make(map[any]any, len(x))
		for k, v := range x {
			copy[k] = cloneConfig(v)
		}
		return copy
	case []any:
		copy := make([]any, len(x))
		for i, v := range x {
			copy[i] = cloneConfig(v)
		}
		return copy
	default:
		return v
	}
}

// YAML integers and JSON integers have different Go types. Compare them exactly
// without converting to float64 (which would lose credentials/IDs above 2^53).
func equalConfig(a, b any) bool {
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for key, v := range x {
			other, exists := y[key]
			if !exists || !equalConfig(v, other) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i, v := range x {
			if !equalConfig(v, y[i]) {
				return false
			}
		}
		return true
	}
	if a != nil && b != nil {
		x, y := reflect.ValueOf(a), reflect.ValueOf(b)
		signed := func(v reflect.Value) bool { return v.Kind() >= reflect.Int && v.Kind() <= reflect.Int64 }
		unsigned := func(v reflect.Value) bool { return v.Kind() >= reflect.Uint && v.Kind() <= reflect.Uint64 }
		if signed(x) && signed(y) {
			return x.Int() == y.Int()
		}
		if unsigned(x) && unsigned(y) {
			return x.Uint() == y.Uint()
		}
		if signed(x) && unsigned(y) {
			return x.Int() >= 0 && uint64(x.Int()) == y.Uint()
		}
		if unsigned(x) && signed(y) {
			return y.Int() >= 0 && x.Uint() == uint64(y.Int())
		}
	}
	return reflect.DeepEqual(a, b)
}

// SnapshotJSON reuses the immutable JSON for nodes/groups/rules, but recomputes
// profile permissions, traffic and expiry on every request.
func (r *Repository) SnapshotJSON(id string) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	entry, _, err := r.cachedEntry(p)
	if err != nil {
		return nil, err
	}
	base := entry.snapshotJSON
	if base == nil {
		base, err = json.Marshal(snapshotBase(entry.doc))
		if err != nil {
			return nil, err
		}
		path := filepath.Clean(p.Files[0])
		if r.cache[path] == entry && r.cacheBytes+len(base) <= configCacheBudget {
			entry.snapshotJSON = base
			entry.weight += len(base)
			r.cacheBytes += len(base)
		}
	}
	updated := ""
	if info, e := os.Stat(p.Files[0]); e == nil {
		updated = info.ModTime().Format("2006-01-02 15:04:05")
	}
	metadata, err := json.Marshal(Document{"profile": public(p), "updated": updated})
	if err != nil {
		return nil, err
	}
	result := make([]byte, 0, len(base)+len(metadata))
	result = append(result, base[:len(base)-1]...)
	result = append(result, ',')
	result = append(result, metadata[1:]...)
	return append(result, '\n'), nil
}
