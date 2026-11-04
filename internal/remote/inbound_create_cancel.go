package remote

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

// CancelUnsentCreates fences operations that have not begun remote writes.
// Pending standalone writes and confirmed inbounds remain recoverable.
func (m *Manager) CancelUnsentCreates(profile string, requests []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	wanted := make(map[string]bool, len(requests))
	changed := false
	for _, operation := range requests {
		key, _, err := createRequestIdentity(profile, Record{"operationId": operation})
		if err != nil {
			return err
		}
		wanted[key] = true
		entry, _ := journal[key].(Record)
		if entry != nil {
			if entry["scope"] != profile {
				return errors.New("主备路径创建记录归属不一致")
			}
			switch entry["status"] {
			case "canceled":
				continue
			case "prepared":
			default:
				return errors.New("部分路径已发送远端创建请求，请先继续创建并核对结果，再删除主备组")
			}
		} else if len(journal) >= 4096 {
			return errors.New("入站创建历史已达上限，无法保存取消记录")
		}
		journal[key] = Record{"scope": profile, "status": "canceled"}
		changed = true
	}
	if !changed {
		return nil
	}
	if err := m.checkCoreCreatesUnsent(wanted); err != nil {
		return err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}

// The cancellation fence and the durable SSH intent share the manager mutex.
func (m *Manager) reserveCoreCreate(server, key, state, pending string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	if entry, _ := journal[key].(Record); entry != nil {
		if entry["status"] == "canceled" {
			return errors.New("此入站创建请求已取消")
		}
		return errors.New("此创建请求已在面板登记，请核对原服务器")
	}
	return m.updateCoreUserStateLocked(server, state, "", state, pending)
}

func (m *Manager) checkCoreCreatesUnsent(wanted map[string]bool) error {
	data, err := m.load()
	if err != nil {
		return err
	}
	sent := errors.New("部分独立内核路径已进入远端写入流程，请先继续创建并核对结果")
	for _, item := range data["servers"].([]any) {
		record, ok := item.(Record)
		if !ok {
			return errors.New("服务器记录格式无效，未取消主备草稿")
		}
		if token := value(record["coreUserPending"]); token != "" {
			intent, err := m.OpenUser(token)
			if err != nil {
				return err
			}
			if intent["operation"] == coreInboundCreate && wanted[value(intent["key"])] {
				return sent
			}
		}
		if value(record["coreState"]) == "" {
			continue
		}
		saved, err := m.Secret(record, "coreState")
		if err != nil {
			return err
		}
		state, err := parseLegacyCoreState(saved)
		if err != nil {
			return err
		}
		for _, row := range state.Inbounds {
			if wanted[value(row["goCreateKey"])] {
				return sent
			}
		}
	}
	return nil
}
