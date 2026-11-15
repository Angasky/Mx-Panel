package remote

import (
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
	"golang.org/x/crypto/ssh"
	"regexp"
)

// EnableAgentManagement upgrades only an enrolled inventory record. The caller
// verifies a pinned SSH connection before invoking this atomic inventory write.
func (m *Manager) EnableAgentManagement(id, private, fingerprint string, port int, previousRevision string) (Record, error) {
	if port < 1 || port > 65535 || !regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`).MatchString(fingerprint) || len(private) > 16384 {
		return nil, errors.New("SSH 管理参数无效")
	}
	if _, e := ssh.ParsePrivateKey([]byte(private)); e != nil {
		return nil, errors.New("SSH 管理密钥无效")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return nil, e
	}
	row, e := find(data, id)
	if e != nil {
		return nil, e
	}
	if row["agentManaged"] == true {
		old, e := m.Secret(row, "sshPrivateKey")
		p, _ := parsedPort(row["sshPort"], 22)
		if e != nil || old != private || value(row["fingerprint"]) != fingerprint || p != port {
			return nil, errors.New("管理连接已变更，请通过管理员连接设置修改")
		}
		return row, nil
	}
	if row["agentOnly"] != true {
		return nil, errors.New("只允许补齐 Agent 接入服务器的管理权限")
	}
	sealed, e := legacycrypto.EncryptFernet(m.key, []byte(private))
	if e != nil {
		return nil, e
	}
	row["agentOnly"] = false
	row["agentManaged"] = true
	row["agentPreviousRevision"] = previousRevision
	row["sshPrivateKey"] = sealed
	row["sshUser"] = "root"
	row["sshPort"] = port
	row["fingerprint"] = fingerprint
	row["installType"] = "xray"
	row["connectionMode"] = "install"
	if e = m.flush(data); e != nil {
		return nil, e
	}
	return row, nil
}
