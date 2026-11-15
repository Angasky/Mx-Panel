package remote

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

type CFZone struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type CFSettings struct {
	Secret   string   `json:"secret,omitempty"`
	Email    string   `json:"email"`
	Zones    []CFZone `json:"zones"`
	Revision string   `json:"revision"`
}

func cfSettings(data map[string]any) (CFSettings, error) {
	c := CFSettings{Zones: []CFZone{}}
	if data["cloudflare"] != nil {
		b, e := json.Marshal(data["cloudflare"])
		if e != nil {
			return c, e
		}
		if e = json.Unmarshal(b, &c); e != nil {
			return c, e
		}
	}
	c.Revision = ""
	b, _ := json.Marshal(c)
	h := sha256.Sum256(b)
	c.Revision = hex.EncodeToString(h[:])
	return c, nil
}
func (m *Manager) CloudflareSettings() (CFSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return CFSettings{}, e
	}
	return cfSettings(data)
}
func (m *Manager) CloudflareKey(c CFSettings) (string, error) {
	b, e := legacycrypto.DecryptFernet(m.key, c.Secret)
	if e != nil {
		return "", errors.New("CF 凭据不可用，请重新保存")
	}
	return string(b), nil
}
func (m *Manager) SaveCloudflare(expected, key, email string, zones []CFZone, remove bool) (CFSettings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return CFSettings{}, e
	}
	c, e := cfSettings(data)
	if e != nil {
		return c, e
	}
	if c.Revision != expected {
		return c, errors.New("CF 设置已变化，请刷新后重试")
	}
	if remove {
		c = CFSettings{Zones: []CFZone{}}
	} else if key != "" {
		c.Secret, e = legacycrypto.EncryptFernet(m.key, []byte(key))
		if e != nil {
			return c, e
		}
		c.Email = email
		c.Zones = []CFZone{}
	} else if zones != nil {
		c.Zones = zones
	}
	c.Revision = ""
	data["cloudflare"] = c
	if e = m.flush(data); e != nil {
		return c, e
	}
	return cfSettings(data)
}
