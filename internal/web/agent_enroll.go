package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

//go:embed agent_enroll_install.sh
var agentEnrollScript string

func enrollHash(value string) string {
	h := sha256.Sum256([]byte(value))
	return hex.EncodeToString(h[:])
}
func shellLiteral(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func (s *Server) agentEnrollAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent/enroll" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil {
		problem(w, 500, "Agent 登记读取失败")
		return true
	}
	switch r.Method {
	case "POST":
		var input struct {
			Reusable         bool   `json:"reusable"`
			Name             string `json:"name"`
			SettingsRevision string `json:"settingsRevision"`
			Origin           string `json:"origin"`
		}
		if e := readJSON(w, r, &input); e != nil {
			problem(w, 400, e.Error())
			return true
		}
		settings, err := s.readAgentEnrollSettings()
		if err != nil {
			problem(w, 500, "Agent 接入设置读取失败")
			return true
		}
		if input.SettingsRevision != "" && input.SettingsRevision != settings.revision() {
			problem(w, 409, "接入设置已变更，请刷新页面后生成命令")
			return true
		}
		name := strings.TrimSpace(input.Name)
		if settings.AutoHostname || input.Reusable {
			name = "等待服务器上报 hostname"
		}
		if name == "" || utf8.RuneCountInString(name) > 60 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
			problem(w, 400, "服务器名称须为 1–60 个字符且不能换行")
			return true
		}
		origin, e := normalizeSubscriptionOrigin(input.Origin)
		u, _ := url.Parse(origin)
		if e != nil || origin == "" || u == nil || !strings.EqualFold(u.Host, r.Host) {
			problem(w, 400, "请使用当前面板的 HTTPS 域名生成命令，不使用独立订阅域名或 IP")
			return true
		}
		// Expired unclaimed entries can be removed safely: they never created servers.
		for id, entry := range entries {
			if entry.EnrollDigest != "" && !entry.EnrollDone && entry.EnrollClient == "" && !entry.EnrollReusable && entry.EnrollExpires <= s.now().Unix() {
				delete(entries, id)
			}
		}
		pending := 0
		for _, entry := range entries {
			if entry.EnrollDigest != "" && !entry.EnrollDone {
				pending++
			}
		}
		if len(entries) >= 1000 || pending >= 50 {
			problem(w, 409, "待接入命令或 Agent 数量已达上限，请先撤销未使用命令")
			return true
		}
		random := make([]byte, 44)
		if _, e := rand.Read(random); e != nil {
			problem(w, 500, "登记凭据生成失败")
			return true
		}
		id := hex.EncodeToString(random[:12])
		token := base64.RawURLEncoding.EncodeToString(random[12:])
		entry := agentRegistration{EnrollAutoHostname: settings.AutoHostname, EnrollDigest: enrollHash(token), EnrollExpires: s.now().Add(30 * time.Minute).Unix(), EnrollName: name, EnrollOrigin: origin}
		if input.Reusable {
			entry.EnrollReusable = true
			entry.EnrollAutoHostname = true
			entry.EnrollExpires = 0
			entry.EnrollName = "多服务器接入令牌"
		}
		entries[id] = entry
		if s.writeAgents(entries) != nil {
			problem(w, 500, "登记凭据保存失败")
			return true
		}
		// Token goes through stdin, not a URL, curl argv or service command line.
		command := "bash -c " + shellLiteral("set -e; umask 077; t=$(mktemp); trap 'rm -f \"$t\"' EXIT; curl -fsS --proto '=https' --connect-timeout 15 --max-time 60 "+shellLiteral(origin+"/sub/agent-install.sh")+" -o \"$t\"; printf '%s\\n' "+shellLiteral(token)+" | bash \"$t\" "+shellLiteral(origin)+" "+shellLiteral(id))
		respond(w, 201, map[string]any{"id": id, "name": name, "expires": entry.EnrollExpires, "reusable": entry.EnrollReusable, "command": command})
		return true
	case "GET":
		m, err := s.remoteManager()
		if err != nil {
			problem(w, 500, "服务器列表不可用")
			return true
		}
		servers, err := m.List()
		if err != nil {
			problem(w, 500, "服务器列表不可用")
			return true
		}
		present := map[string]bool{}
		for _, row := range servers {
			present[stringField(row, "id")] = true
		}
		rows := []map[string]any{}
		for id, entry := range entries {
			if entry.EnrollDigest == "" {
				continue
			}
			status := "waiting"
			if entry.EnrollDone {
				status = "registered"
			} else if entry.EnrollReusable {
				status = "reusable"
			} else if entry.EnrollExpires > 0 && entry.EnrollExpires <= s.now().Unix() {
				status = "expired"
			}
			v := s.agentViews[id]
			connected := entry.Enabled && entry.EnrollDone && v.Digest == entry.Digest && !v.At.IsZero() && s.now().Sub(v.At) < 90*time.Second
			if entry.EnrollDone && !present[id] {
				status = "removed"
				connected = false
			}
			count := 0
			for _, child := range entries {
				if child.EnrollParent == id && child.EnrollDone {
					count++
				}
			}
			rows = append(rows, map[string]any{"reusable": entry.EnrollReusable, "registeredCount": count, "parent": entry.EnrollParent, "id": id, "name": entry.EnrollName, "expires": entry.EnrollExpires, "status": status, "connected": connected})
		}
		respond(w, 200, map[string]any{"entries": rows})
		return true
	case "DELETE":
		id := r.URL.Query().Get("id")
		entry, ok := entries[id]
		if !ok || entry.EnrollDigest == "" {
			problem(w, 404, "登记命令不存在")
			return true
		}
		if entry.EnrollDone {
			problem(w, 409, "服务器已登记，请在 Agent 接入中撤销凭据，或移除该服务器")
			return true
		}
		delete(entries, id)
		if s.writeAgents(entries) != nil {
			problem(w, 500, "撤销失败")
			return true
		}
		respond(w, 200, map[string]any{"ok": true})
		return true
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
}
func (s *Server) agentEnrollPublic(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/sub/agent-install.sh" {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Write([]byte(agentEnrollScript))
		return true
	}
	if r.URL.Path != "/sub/agent-enroll" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.secure(r) {
		problem(w, 426, "Agent 接入必须使用 HTTPS")
		return true
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	// Do not accept cookies, query tokens, or multiple Authorization headers.
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strings.HasPrefix(values[0], "Bearer ") {
		problem(w, 401, "接入凭据无效")
		return true
	}
	token := strings.TrimPrefix(values[0], "Bearer ")
	if len(token) != 43 {
		problem(w, 401, "接入凭据无效")
		return true
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	var input struct {
		ID             string `json:"id"`
		Client         string `json:"client"`
		HostnameBase64 string `json:"hostnameBase64"`
	}
	if e := readJSON(w, r, &input); e != nil {
		problem(w, 400, "接入请求无效")
		return true
	}
	raw, e := hex.DecodeString(input.Client)
	if e != nil || len(raw) != 32 {
		problem(w, 400, "安装实例标识无效")
		return true
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	entry, ok := entries[input.ID]
	if e != nil || !ok || entry.EnrollDigest == "" || (!entry.EnrollReusable && entry.EnrollExpires <= s.now().Unix()) || subtle.ConstantTimeCompare([]byte(entry.EnrollDigest), []byte(enrollHash(token))) != 1 {
		problem(w, 401, "命令已过期、已撤销或凭据无效")
		return true
	}

	if entry.EnrollReusable {
		parentID := input.ID
		childID := enrollHash("mx-enroll-child-v1:" + parentID + ":" + input.Client)[:24]
		child, exists := entries[childID]
		if exists {
			if child.EnrollParent != parentID {
				problem(w, 409, "安装实例身份冲突")
				return true
			}
		} else {
			if len(entries) >= 1000 {
				problem(w, 409, "Agent 数量已达上限")
				return true
			}
			child = agentRegistration{EnrollParent: parentID, EnrollAutoHostname: true, EnrollDigest: entry.EnrollDigest, EnrollOrigin: entry.EnrollOrigin}
		}
		input.ID = childID
		entry = child
	}
	clientHash := enrollHash(input.Client)
	if entry.EnrollClient != "" && entry.EnrollClient != clientHash {
		problem(w, 409, "此命令已被另一安装实例使用，请生成新命令")
		return true
	}
	agentToken := base64.RawURLEncoding.EncodeToString(func() []byte { h := sha256.Sum256([]byte("mx-agent-v1:" + token + ":" + input.Client)); return h[:] }())
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器列表不可用")
		return true
	}
	if !entry.EnrollDone {
		if entry.EnrollClient == "" {
			if entry.EnrollAutoHostname {
				name, err := decodeEnrollHostname(input.HostnameBase64)
				if err != nil {
					problem(w, 400, err.Error())
					return true
				}
				entry.EnrollName = name
			}
			ip, _ := s.subscriptionClientIP(r)
			if net.ParseIP(ip) == nil {
				problem(w, 400, "无法识别接入来源 IP，请检查反向代理")
				return true
			}
			entry.EnrollHost = ip
			entry.EnrollClient = clientHash
			entries[input.ID] = entry
			if s.writeAgents(entries) != nil {
				problem(w, 500, "接入登记保存失败")
				return true
			}
		}
		record, e := m.RegisterAgent(input.ID, entry.EnrollName, entry.EnrollHost)
		if e != nil {
			problem(w, 409, "服务器登记失败，请在面板核查接入记录")
			return true
		}
		entry.Enabled = true
		entry.Mode = "auto"
		entry.Digest = enrollHash(agentToken)
		entry.Revision = agentServerRevision(record)
		entry.EnrollDone = true
		entries[input.ID] = entry
		if s.writeAgents(entries) != nil {
			problem(w, 500, "Agent 凭据保存失败，可使用同一安装实例重试")
			return true
		}
	} else {
		if !entry.Enabled || entry.Digest != enrollHash(agentToken) {
			problem(w, 409, "Agent 凭据已变化，不可重放旧命令")
			return true
		}
		record, e := m.Record(input.ID)
		if e != nil || entry.Revision != agentServerRevision(record) {
			problem(w, 409, "服务器已移除或身份变化")
			return true
		}
	}
	observation := s.agentViews[input.ID]
	if observation.Digest == entry.Digest && !observation.At.IsZero() && s.now().Sub(observation.At) < 90*time.Second {
		w.Header().Set("X-Mxioc-Agent-Connected", "true")
	}
	config := map[string]any{"url": entry.EnrollOrigin + "/sub/agent/" + input.ID, "token": agentToken, "mode": "auto"}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(config)
	return true
}
