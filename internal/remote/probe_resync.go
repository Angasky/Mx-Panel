package remote

import (
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"time"
)

// UpdateProbeHost commits only the management address after the caller verifies
// the existing host key and credential at that address. Concurrent edits abort.
func (m *Manager) UpdateProbeHost(expected Record, host string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id := value(expected["id"])
	if value(expected["probeUUID"]) == "" || value(expected["probeSource"]) == "" || net.ParseIP(host) == nil || !validHost(host) {
		return nil, errors.New("探针服务器或地址无效")
	}
	data, e := m.load()
	if e != nil {
		return nil, e
	}
	record, e := find(data, id)
	if e != nil {
		return nil, e
	}
	a, _ := json.Marshal(record)
	b, _ := json.Marshal(expected)
	if !bytes.Equal(a, b) {
		return nil, errors.New("服务器配置已变化，请重新同步")
	}
	if gate := m.operations[id]; gate != nil && len(gate) > 0 {
		return nil, errors.New("服务器正在执行操作，请稍后重新同步")
	}
	for _, raw := range data["jobs"].([]any) {
		job, ok := raw.(map[string]any)
		if ok && job["serverId"] == id && (job["status"] == "running" || job["status"] == "queued") {
			return nil, errors.New("服务器部署任务尚未结束，请稍后同步")
		}
	}
	if value(record["coreUserPending"]) != "" {
		return nil, errors.New("服务器有待核对的用户变更，请先完成核对")
	}
	for _, raw := range data["servers"].([]any) {
		other, ok := raw.(map[string]any)
		if ok && other["id"] != id && value(other["host"]) == host && value(other["sshPort"]) == value(record["sshPort"]) {
			return nil, errors.New("新地址与端口已由其他服务器登记，请先核对重复记录")
		}
	}
	record["host"] = host
	record["probeSyncedAt"] = time.Now().Unix()
	if e = m.flush(data); e != nil {
		return nil, e
	}
	return publicServer(record), nil
}
