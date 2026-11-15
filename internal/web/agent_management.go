package web

import (
	"crypto/subtle"
	_ "embed"
	"encoding/base64"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/http"
	"strings"
)

//go:embed agent_management_install.sh
var agentManagementScript string

func (s *Server) agentManagementPublic(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/sub/agent-management.sh" {
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
		w.Write([]byte(agentManagementScript))
		return true
	}
	const prefix = "/sub/agent-manage/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.secure(r) {
		problem(w, 426, "管理授权必须使用 HTTPS")
		return true
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := strings.TrimPrefix(r.URL.Path, prefix)
	headers := r.Header.Values("Authorization")
	if len(headers) != 1 || !strings.HasPrefix(headers[0], "Bearer ") {
		problem(w, 401, "Agent 凭据无效")
		return true
	}
	token := strings.TrimPrefix(headers[0], "Bearer ")
	if len(token) != 43 {
		problem(w, 401, "Agent 凭据无效")
		return true
	}
	s.agentMu.Lock()
	entries, e := s.readAgents()
	entry, ok := entries[id]
	s.agentMu.Unlock()
	if e != nil || !ok || !entry.Enabled || !entry.EnrollDone || subtle.ConstantTimeCompare([]byte(entry.Digest), []byte(enrollHash(token))) != 1 {
		problem(w, 401, "Agent 已撤销或不是命令接入服务器")
		return true
	}
	var input struct {
		Private     string `json:"privateKeyBase64"`
		Fingerprint string `json:"fingerprint"`
		Port        int    `json:"port"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, 24576)
	if readJSON(w, r, &input) != nil {
		problem(w, 400, "管理授权参数无效")
		return true
	}
	raw, e := base64.StdEncoding.DecodeString(input.Private)
	if e != nil || len(raw) > 16384 || input.Port < 1 || input.Port > 65535 {
		problem(w, 400, "SSH 密钥或端口无效")
		return true
	}
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器记录不可用")
		return true
	}
	row, e := m.Record(id)
	if e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	revision := agentServerRevision(row)
	// A crash between the two durable writes can be repaired only by the same
	// enrollment and the identical connection (checked by EnableAgentManagement).
	if revision != entry.Revision && !(row["agentManaged"] == true && stringField(row, "agentPreviousRevision") == entry.Revision) {
		problem(w, 409, "服务器身份已变更")
		return true
	}
	conn := remote.Connection{Host: stringField(row, "host"), User: "root", Port: input.Port, PrivateKey: string(raw), Fingerprint: input.Fingerprint}
	client, e := remote.Connect(r.Context(), conn)
	if e != nil {
		problem(w, 409, "SSH 管理连接验证失败："+e.Error()+"；请检查 SSH 端口、防火墙和 root 公钥登录。监控仍可用")
		return true
	}
	client.Close()
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e = s.readAgents()
	current, ok := entries[id]
	if e != nil || !ok || !current.Enabled || current.Digest != entry.Digest || current.Revision != entry.Revision {
		problem(w, 409, "验证期间 Agent 授权已变化")
		return true
	}
	latest, e := m.Record(id)
	if e != nil || agentServerRevision(latest) != revision {
		problem(w, 409, "验证期间服务器已变化")
		return true
	}
	row, e = m.EnableAgentManagement(id, string(raw), input.Fingerprint, input.Port, entry.Revision)
	if e != nil {
		problem(w, 409, e.Error())
		return true
	}
	current.Revision = agentServerRevision(row)
	entries[id] = current
	if s.writeAgents(entries) != nil {
		problem(w, 500, "授权状态保存失败，请重新运行同一命令恢复")
		return true
	}
	respond(w, 200, map[string]any{"ok": true, "message": "SSH 管理权限已启用，可部署 Xray、sing-box 和管理节点/中转"})
	return true
}
