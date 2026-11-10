package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type serverMetadata struct {
	Region      string   `json:"region"`
	Provider    string   `json:"provider"`
	ProviderURL string   `json:"providerURL"`
	Expires     string   `json:"expires"`
	Price       *float64 `json:"price"`
	Currency    string   `json:"currency"`
	Cycle       string   `json:"cycle"`
	Public      bool     `json:"public"`
}

func validateMetadata(m serverMetadata) error {
	for _, s := range []string{m.Region, m.Provider} {
		if !utf8.ValidString(s) || len([]rune(s)) > 80 || strings.TrimSpace(s) != s || strings.ContainsFunc(s, unicode.IsControl) {
			return errors.New("地域和服务商最多 80 个字符，不能含控制字符或首尾空格")
		}
	}
	if m.ProviderURL != "" {
		u, e := url.Parse(m.ProviderURL)
		if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || len(m.ProviderURL) > 500 || strings.ContainsAny(m.ProviderURL, "\r\n") {
			return errors.New("服务商链接必须是 HTTPS 地址")
		}
	}
	if m.Expires != "" {
		if t, e := time.Parse("2006-01-02", m.Expires); e != nil || t.Year() < 2000 || t.Year() > 2200 {
			return errors.New("到期日期格式为 YYYY-MM-DD")
		}
	}
	if m.Price != nil && (math.IsNaN(*m.Price) || math.IsInf(*m.Price, 0) || *m.Price < 0 || *m.Price > 100000000) {
		return errors.New("费用必须在 0 到 100000000 之间")
	}
	if m.Currency != "" && !strings.Contains("|CNY|USD|EUR|GBP|JPY|HKD|TWD|SGD|CAD|AUD|", "|"+m.Currency+"|") {
		return errors.New("不支持的币种")
	}
	switch m.Cycle {
	case "", "month", "quarter", "half-year", "year", "one-time":
	default:
		return errors.New("计费周期无效")
	}
	if m.Price != nil && (m.Currency == "" || m.Cycle == "") {
		return errors.New("填写费用后还需选择币种和计费周期")
	}
	return nil
}
func (s *Server) metadataPath(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.options.Root, "server-metadata-"+hex.EncodeToString(sum[:])+".json")
}
func (s *Server) readMetadata(id string) (serverMetadata, error) {
	var m serverMetadata
	b, e := os.ReadFile(s.metadataPath(id))
	if os.IsNotExist(e) {
		return m, nil
	}
	if e != nil {
		return m, e
	}
	if len(b) > 8192 {
		return m, errors.New("元信息过大")
	}
	if e = json.Unmarshal(b, &m); e != nil {
		return m, e
	}
	return m, validateMetadata(m)
}
func (s *Server) metadataRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/metadata" {
		return false
	}
	if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	manager, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	if _, e = manager.Record(id); e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	s.metadataMu.Lock()
	defer s.metadataMu.Unlock()
	if r.Method == "PUT" {
		var m serverMetadata
		if readJSON(w, r, &m) != nil {
			problem(w, 400, "元信息格式无效")
			return true
		}
		if e = validateMetadata(m); e != nil {
			problem(w, 400, e.Error())
			return true
		}
		b, _ := json.Marshal(m)
		f, err := os.CreateTemp(s.options.Root, ".server-meta-*")
		if err != nil {
			problem(w, 500, "保存失败")
			return true
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if _, err = f.Write(b); err == nil {
			err = f.Sync()
		}
		if err == nil {
			err = f.Close()
		}
		if err == nil {
			err = os.Rename(f.Name(), s.metadataPath(id))
		}
		if err != nil {
			problem(w, 500, "保存失败")
			return true
		}
	}
	if r.Method == "DELETE" {
		if e = os.Remove(s.metadataPath(id)); e != nil && !os.IsNotExist(e) {
			problem(w, 500, "清除失败")
			return true
		}
	}
	m, e := s.readMetadata(id)
	if e != nil {
		problem(w, 500, "元信息读取失败")
		return true
	}
	respond(w, 200, m)
	return true
}
