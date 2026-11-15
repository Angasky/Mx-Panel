package remote

import "errors"

// BindNodeDomain updates only the default node address, never SSH identity or TLS SNI.
func (m *Manager) BindNodeDomain(id, host, previous, domain string) error {
	if !validHost(domain) {
		return errors.New("节点域名无效")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return e
	}
	row, e := find(data, id)
	if e != nil {
		return e
	}
	if value(row["host"]) != host || value(row["nodeAddress"]) != previous {
		return errors.New("服务器地址已被其他操作修改，请刷新")
	}
	row["nodeAddress"] = domain
	return m.flush(data)
}
