package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
)

type agentEnrollSettings struct {
	AutoHostname bool `json:"autoHostname"`
}

func (c agentEnrollSettings) revision() string { b, _ := json.Marshal(c); return enrollHash(string(b)) }
func (s *Server) readAgentEnrollSettings() (agentEnrollSettings, error) {
	var c agentEnrollSettings
	b, e := os.ReadFile(filepath.Join(s.options.Root, "agent-enroll-settings.json"))
	if os.IsNotExist(e) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	if len(b) > 1024 || string(b) == "null" {
		return c, errors.New("Agent 接入设置损坏")
	}
	var stored struct {
		AutoHostname *bool `json:"autoHostname"`
	}
	if e = json.Unmarshal(b, &stored); e != nil || stored.AutoHostname == nil {
		return c, errors.New("Agent 接入设置损坏")
	}
	c.AutoHostname = *stored.AutoHostname
	return c, nil
}
func (s *Server) agentEnrollSettingsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent/enroll-settings" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	c, e := s.readAgentEnrollSettings()
	if e != nil {
		problem(w, 500, "Agent 接入设置读取失败")
		return true
	}
	switch r.Method {
	case "GET":
	case "PUT":
		var input struct {
			AutoHostname *bool  `json:"autoHostname"`
			Revision     string `json:"revision"`
		}
		if e := readJSON(w, r, &input); e != nil || input.AutoHostname == nil {
			problem(w, 400, "请提供自动检测主机名开关")
			return true
		}
		if input.Revision != c.revision() {
			problem(w, 409, "设置已变更，请刷新后重试")
			return true
		}
		c.AutoHostname = *input.AutoHostname
		f, e := os.CreateTemp(s.options.Root, ".agent-enroll-settings-*")
		if e != nil {
			problem(w, 500, "设置保存失败")
			return true
		}
		defer os.Remove(f.Name())
		b, _ := json.Marshal(c)
		_, e = f.Write(b)
		if e == nil {
			e = f.Sync()
		}
		closeErr := f.Close()
		if e == nil {
			e = closeErr
		}
		if e == nil {
			e = os.Rename(f.Name(), filepath.Join(s.options.Root, "agent-enroll-settings.json"))
		}
		if e != nil {
			problem(w, 500, "设置保存失败")
			return true
		}
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	respond(w, 200, map[string]any{"autoHostname": c.AutoHostname, "revision": c.revision()})
	return true
}

var enrollHostnamePattern = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]{0,252}$`)

func decodeEnrollHostname(encoded string) (string, error) {
	if len(encoded) > 340 {
		return "", errors.New("hostname 超过长度限制")
	}
	b, e := base64.StdEncoding.Strict().DecodeString(encoded)
	if e != nil || !enrollHostnamePattern.Match(b) {
		return "", errors.New("未收到有效 hostname，请更新安装脚本；仅支持 1–253 位字母、数字、点、连字符和下划线")
	}
	return string(b), nil
}
