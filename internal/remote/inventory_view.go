package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"time"
)

type inventoryViewEntry struct {
	revision string
	data     []byte
	at       time.Time
	loading  chan struct{}
}

// Display-only snapshots must never feed reconciliation, billing, or writes.
// Authoritative callers continue using Inbounds, without this cache.
func (m *Manager) InboundsView(ctx context.Context, id string, force bool) (Record, error) {
	return m.inventoryView(ctx, id, force, func(ctx context.Context) (Record, error) {
		if force {
			ctx = context.WithValue(ctx, probeRefreshKey{}, true)
		}
		return m.InboundsWithStats(context.WithValue(ctx, inventoryWaitKey{}, true), id)
	})
}
func (m *Manager) inventoryView(ctx context.Context, id string, force bool, load func(context.Context) (Record, error)) (Record, error) {
	for {
		record, err := m.Record(id)
		if err != nil {
			return nil, err
		}
		revision := RegistrationFingerprint(record)
		m.mu.Lock()
		if m.inventoryViews == nil {
			m.inventoryViews = map[string]*inventoryViewEntry{}
		}
		entry := m.inventoryViews[id]
		busy := len(m.operations[id]) > 0
		if entry != nil && entry.revision == revision && len(entry.data) > 0 && ((!force && time.Since(entry.at) < 5*time.Second) || (busy && time.Since(entry.at) < 60*time.Second)) {
			raw := append([]byte(nil), entry.data...)
			at := entry.at
			m.mu.Unlock()
			result := Record{}
			decoder := json.NewDecoder(bytes.NewReader(raw))
			decoder.UseNumber()
			if err := decoder.Decode(&result); err != nil {
				return nil, err
			}
			result["viewCached"] = true
			result["viewStale"] = busy
			result["viewSampledAt"] = at.Unix()
			return result, nil
		}
		if entry != nil && entry.loading != nil {
			done := entry.loading
			m.mu.Unlock()
			select {
			case <-done:
				force = false
				continue
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		if entry == nil {
			entry = &inventoryViewEntry{}
			m.inventoryViews[id] = entry
		}
		done := make(chan struct{})
		entry.loading = done
		m.mu.Unlock()
		result, err := load(ctx)
		raw, _ := json.Marshal(result)
		m.mu.Lock()
		entry.loading = nil
		if err == nil {
			entry.revision = revision
			entry.data = raw
			entry.at = time.Now()
			result["viewSampledAt"] = entry.at.Unix()
		}
		close(done)
		if len(m.inventoryViews) > 64 {
			for key, v := range m.inventoryViews {
				if key != id && v.loading == nil {
					delete(m.inventoryViews, key)
					break
				}
			}
		}
		m.mu.Unlock()
		return result, err
	}
}

// Keep a concurrent reader's completion signal, but never retain a snapshot
// across a possible write (including a write whose remote outcome is uncertain).
func (m *Manager) invalidateInventoryView(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if entry := m.inventoryViews[id]; entry != nil {
		entry.data = nil
		entry.revision = ""
	}
}
