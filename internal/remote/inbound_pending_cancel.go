package remote

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strconv"
)

// A cancellation request fences local retries immediately. Sent panel writes
// are reconciled from their encrypted desired config; absence is never proof
// that an in-flight HTTP handler will not finish later.
func (m *Manager) CancelPendingCreates(ctx context.Context, scope string, requests []string, guard func(string, string, int, Record) error) (Record, error) {
	// Fence every path before the first remote call. One offline or uncertain
	// path must not leave later paths eligible for a delayed local reservation.
	keys := make([]string, len(requests))
	for i, request := range requests {
		key, _, err := createRequestIdentity(scope, Record{"operationId": request})
		if err != nil {
			return nil, err
		}
		keys[i] = key
	}
	if err := m.fenceCreateBatch(scope, keys); err != nil {
		return nil, err
	}
	for _, request := range requests {
		key, _, err := createRequestIdentity(scope, Record{"operationId": request})
		if err != nil {
			return nil, err
		}
		entry, err := m.requestCreateCancel(scope, key)
		if err != nil {
			return nil, err
		}
		if entry == nil { // Includes standalone intents; the same mutex fences reserve.
			if err := m.cancelPendingCoreCreate(ctx, scope, key, request, guard); err != nil {
				return nil, err
			}
			continue
		}
		if entry["status"] == "canceled" {
			if entry["coreCleanupPending"] == true {
				if err := m.cancelPendingCoreCreate(ctx, scope, key, request, guard); err != nil {
					return nil, err
				}
			}
			continue
		}
		server := value(entry["serverId"])
		_, err = m.WithPanel(ctx, server, func(p *Panel, record Record) (any, error) {
			return nil, m.cancelPanelCreate(ctx, p, record, scope, key, request, guard)
		})
		if err != nil {
			return nil, err
		}
	}
	return Record{"canceled": true}, nil
}
func (m *Manager) fenceCreateBatch(scope string, keys []string) error {
	if len(keys) == 0 {
		return nil
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	for _, key := range keys {
		if entry, ok := journal[key].(Record); ok {
			if entry["scope"] != scope {
				return errors.New("创建请求归属不一致")
			}
			if entry["status"] != "canceled" {
				entry["cancelRequested"] = true
			}
		} else if _, err := m.prepareCoreCancel(scope, key, journal); err != nil {
			return err
		}
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}

func (m *Manager) requestCreateCancel(scope, key string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return nil, err
	}
	entry, _ := journal[key].(Record)
	if entry == nil {
		return nil, nil
	}
	if entry["scope"] != scope {
		return nil, errors.New("创建请求归属不一致")
	}
	if entry["status"] == "canceled" {
		return entry, nil
	}
	entry["cancelRequested"] = true
	raw, err := json.Marshal(journal)
	if err != nil {
		return nil, err
	}
	if err = write(filepath.Join(m.root, "inbound-creates.json"), raw); err != nil {
		return nil, err
	}
	return entry, nil
}
func (m *Manager) finishCreateCancel(scope, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	entry, _ := journal[key].(Record)
	if entry != nil && entry["scope"] != scope {
		return errors.New("取消归属已变化")
	}
	if entry == nil && len(journal) >= 4096 {
		return errors.New("创建记录已达上限")
	}
	journal[key] = Record{"scope": scope, "status": "canceled"}
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}
func (m *Manager) cancelPanelCreate(ctx context.Context, p *Panel, record Record, scope, key, request string, guard func(string, string, int, Record) error) error {
	entry, err := m.loadCreate(key)
	if err != nil {
		return err
	}
	if entry == nil || entry["scope"] != scope || entry["cancelRequested"] != true || entry["revision"] != createServerRevision(record) {
		return errors.New("取消请求或服务器身份已变化")
	}
	if entry["status"] == "prepared" {
		return m.finishCreateCancel(scope, key)
	}
	relayKey, _ := identity([]any{key, "relay"})
	relayIntent, err := m.loadCreate(relayKey)
	if err != nil {
		return err
	}
	// An unfinished template write can still be followed by its rollback. Do
	// not claim that observing its candidate proves the operation has stopped.
	if relayIntent != nil && relayIntent["status"] != "confirmed" && relayIntent["status"] != "prepared" {
		return errors.New("中转配置写入或回滚仍待核对；取消意图已保存，不会创建后续路径")
	}
	desired, err := m.OpenUser(value(entry["sealedDesired"]))
	if err != nil {
		return err
	}
	rows, err := creationRows(ctx, p)
	if err != nil {
		return err
	}
	var row Record
	if entry["cancelDeletePending"] == true {
		for _, candidate := range rows {
			if value(candidate["id"]) == value(entry["inboundId"]) {
				row = candidate
			}
		}
		if row != nil {
			hash, err := EndpointIdentity(row)
			if err != nil || hash != entry["endpointHash"] {
				return errors.New("待取消入站身份已变化")
			}
		}
	} else {
		row, err = confirmCreation(rows, desired, entry)
		if err != nil {
			return err
		}
		if row == nil {
			return errors.New("创建结果尚未出现；取消意图已保存，等待迟到结果后重试取消")
		}
	}
	id, err := strconv.Atoi(value(entry["inboundId"]))
	if row != nil {
		id, err = strconv.Atoi(value(row["id"]))
	}
	if err != nil || id < 1 {
		return errors.New("待取消入站 ID 无效")
	}
	if err = guard(request, value(record["id"]), id, row); err != nil {
		return err
	}
	expected := value(entry["cancelVersion"])
	if row != nil {
		expected, err = InboundVersion(row)
		if err != nil {
			return err
		}
		hash, err := EndpointIdentity(row)
		if err != nil {
			return err
		}
		entry["cancelDeletePending"], entry["cancelVersion"], entry["inboundId"], entry["endpointHash"] = true, expected, id, hash
		if err = m.saveCanceledCreateIntent(key, entry); err != nil {
			return err
		}
	}
	deleteGuard := func(old Record) error { return guard(request, value(record["id"]), id, old) }
	relays, err := relayRecords(record)
	if err != nil {
		return err
	}
	for _, relay := range relays {
		if value(relay["inboundId"]) == strconv.Itoa(id) {
			if _, err = m.deleteRelayInbound(ctx, p, record, relay, id, expected, deleteGuard); err != nil {
				return err
			}
			return m.finishCreateCancel(scope, key)
		}
	}
	if relayIntent != nil && relayIntent["status"] == "confirmed" {
		return errors.New("已确认中转缺少归属记录，未猜测清理")
	}
	if _, err = deletePanelInbound(ctx, p, record, id, expected, deleteGuard); err != nil {
		return err
	}
	return m.finishCreateCancel(scope, key)
}
func (m *Manager) saveCanceledCreateIntent(key string, entry Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	previous, _ := journal[key].(Record)
	if previous == nil || previous["cancelRequested"] != true || previous["scope"] != entry["scope"] || previous["revision"] != entry["revision"] {
		return errors.New("取消记录已变化")
	}
	journal[key] = entry
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}
