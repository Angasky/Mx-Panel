package web

import (
	"github.com/Angasky/dingzhi-ban/internal/links"
	"net/http"
)

func (s *Server) outboundProbeRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/outbound-test" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == "GET" {
		m, e := s.remoteManager()
		if e != nil {
			problem(w, 500, "服务器管理暂不可用")
			return true
		}
		data, e := m.OutboundProbeTargets(r.Context(), r.URL.Query().Get("serverId"))
		if e != nil {
			problem(w, 400, e.Error())
		} else {
			respond(w, 200, data)
		}
		return true
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		ServerID string `json:"serverId"`
		Link     string `json:"link"`
		Name     string `json:"name"`
		Target   string `json:"target"`
		Tag      string `json:"tag"`
	}
	if readJSON(w, r, &in) != nil || in.ServerID == "" || (in.Name == "") == (in.Link == "") && in.Tag == "" || in.Tag != "" && (in.Name != "" || in.Link != "") {
		problem(w, 400, "请选择服务器，并指定一个订阅节点或分享链接")
		return true
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.nodeProbeMu.TryLock() {
		problem(w, 429, "已有节点测试进行中，请稍后重试")
		return true
	}
	defer s.nodeProbeMu.Unlock()
	if in.Name != "" {
		node, e := s.repository.ProbeNodeConfig(r.Header.Get("X-Profile"), in.Name)
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		in.Link, e = links.Export(node)
		if e != nil {
			problem(w, 400, "所选节点不能导出为兼容的代理测试配置")
			return true
		}
	}
	if in.Target == "" {
		in.Target = "gstatic"
	}
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器管理暂不可用")
		return true
	}
	var result map[string]any
	if in.Tag != "" {
		result, e = m.ProbeConfiguredOutbound(r.Context(), in.ServerID, in.Tag, in.Target)
	} else {
		result, e = m.ProbeOutbound(r.Context(), in.ServerID, in.Link, in.Target)
	}
	if e != nil {
		problem(w, 400, e.Error())
	} else {
		respond(w, 200, result)
	}
	return true
}
