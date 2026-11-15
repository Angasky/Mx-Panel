package remote

import (
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// RegisterAgent creates an explicit SSH-free inventory entry. It never probes
// the supplied address or guesses credentials, and retries preserve identity.
func (m *Manager) RegisterAgent(id, name, host string) (Record, error) {
	if b, e := hex.DecodeString(id); e != nil || len(b) != 12 {
		return nil, errors.New("Agent 登记 ID 无效")
	}
	if strings.TrimSpace(name) == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > 60 || strings.ContainsFunc(name, unicode.IsControl) || net.ParseIP(host) == nil {
		return nil, errors.New("Agent 服务器名称或来源地址无效")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return nil, e
	}
	if existing, e := find(data, id); e == nil {
		if existing["agentOnly"] != true || existing["name"] != name || existing["host"] != host {
			return nil, errors.New("服务器身份已变化")
		}
		return existing, nil
	}
	if len(data["servers"].([]any)) >= 1000 {
		return nil, errors.New("服务器数量已达上限")
	}
	row := Record{"id": id, "name": name, "host": host, "agentOnly": true, "installType": "agent", "connectionMode": "agent", "createdAt": time.Now().Unix()}
	data["servers"] = append(data["servers"].([]any), row)
	if e := m.flush(data); e != nil {
		return nil, e
	}
	return row, nil
}
