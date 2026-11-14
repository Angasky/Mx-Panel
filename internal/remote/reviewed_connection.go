package remote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
)

// RegistrationFingerprint binds an approval to a complete registration snapshot.
func RegistrationFingerprint(record Record) string {
	raw, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	hash := sha256.Sum256(raw)
	return hex.EncodeToString(hash[:])
}

// ReviewedConnection verifies and decrypts the same immutable record. A later
// registry change cannot redirect an already-reviewed SSH operation.
func (m *Manager) ReviewedConnection(id, expected string) (Connection, error) {
	record, err := m.Record(id)
	if err != nil {
		return Connection{}, err
	}
	if expected == "" || RegistrationFingerprint(record) != expected {
		return Connection{}, errors.New("服务器连接资料已变更，请重新生成操作计划")
	}
	return m.connectionRecord(record)
}
