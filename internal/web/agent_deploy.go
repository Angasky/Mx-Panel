package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/agentcontrol"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
	"net/http"
	"net/url"
	"strings"
)

func (s *Server) agentDeploy(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent/deploy" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var input struct {
		ID        string          `json:"id"`
		Confirmed bool            `json:"confirmed"`
		Config    json.RawMessage `json:"config"`
	}
	if readJSON(w, r, &input) != nil || !input.Confirmed || len(input.Config) > 64<<10 {
		problem(w, 400, "请确认 Agent 安装并提供有效配置")
		return true
	}
	var config struct {
		URL     string                         `json:"url"`
		Token   string                         `json:"token"`
		Mode    string                         `json:"mode"`
		Targets map[string]agentcontrol.Target `json:"targets"`
		Probes  []netprobe.Target              `json:"probes"`
	}
	if json.Unmarshal(input.Config, &config) != nil {
		problem(w, 400, "配置无效")
		return true
	}
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器不可用")
		return true
	}
	record, e := m.Record(input.ID)
	if e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	digest, ok := s.agentAuthorized(input.ID, config.Token)
	if !ok {
		problem(w, 400, "Agent 凭据无效或已轮换")
		return true
	}
	endpoint, e := url.Parse(config.URL)
	if e != nil || endpoint.Scheme != "https" || !strings.EqualFold(endpoint.Host, r.Host) || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || endpoint.Path != "/sub/agent/"+input.ID {
		problem(w, 400, "Agent 地址必须为当前面板的 HTTPS 接口")
		return true
	}
	if netprobe.Validate(config.Probes) != nil || len(config.Targets) > 16 {
		problem(w, 400, "探测或服务授权配置无效")
		return true
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	entry := entries[input.ID]
	if e != nil || !entry.Enabled || entry.Digest != digest || entry.Mode != config.Mode || entry.Revision != agentServerRevision(record) {
		problem(w, 409, "Agent 配置或服务器身份已变化")
		return true
	}
	canonical, _ := json.Marshal(json.RawMessage(input.Config))
	hash := sha256.Sum256(canonical)
	configHash := hex.EncodeToString(hash[:])
	if entry.DeployJob != "" {
		if previous, e := m.InstallJob(entry.DeployJob); e == nil && (previous["status"] == "running" || previous["status"] == "queued" || previous["status"] == "succeeded" && entry.DeployHash == configHash) {
			respond(w, 202, map[string]any{"job": previous})
			return true
		}
	}
	job, e := m.StartAgentInstall(input.ID, input.Config, entry.Revision)
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	entry.DeployJob = job["id"].(string)
	entry.DeployHash = configHash
	entries[input.ID] = entry
	if e = s.writeAgents(entries); e != nil {
		problem(w, 500, "安装已启动，但任务关联保存失败；请到服务器安装任务查看状态")
		return true
	}
	respond(w, 202, map[string]any{"job": job})
	return true
}
