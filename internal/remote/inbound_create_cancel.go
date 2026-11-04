package remote

import (
	"encoding/json"
	"errors"
	"path/filepath"
)

// CancelUnsentCreates atomically fences requests that have never sent an
// inbound creation to the panel. Sent operations remain recoverable.
func (m *Manager) CancelUnsentCreates(profile string, requests []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return err
	}
	changed := false
	for _, operation := range requests {
		key, _, err := createRequestIdentity(profile, Record{"operationId": operation})
		if err != nil {
			return err
		}
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
	raw, err := json.Marshal(journal)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}
