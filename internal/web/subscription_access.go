package web

import (
	"github.com/Angasky/dingzhi-ban/internal/config"
	"net"
	"net/http"
	"net/netip"
)

// Trust only a single X-Real-IP overwritten by the configured loopback proxy.
// Forwarded chains and Cloudflare headers from arbitrary clients are ignored.
func (s *Server) subscriptionClientIP(r *http.Request) (string, string) {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return "", "unknown"
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || peer.Zone() != "" {
		return "", "unknown"
	}
	peer = peer.Unmap()
	if s.options.TrustLoopbackProxy && peer.IsLoopback() {
		values := r.Header.Values("X-Real-IP")
		if len(values) != 1 {
			return "", "proxy-missing"
		}
		ip, err := netip.ParseAddr(values[0])
		if err != nil || ip.Zone() != "" {
			return "", "proxy-invalid"
		}
		return ip.Unmap().String(), "trusted-loopback-proxy"
	}
	return peer.String(), "socket"
}
func (s *Server) subscriptionAccessRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/subscription-access" {
		return false
	}
	id := r.Header.Get("X-Profile")
	var options config.SubscriptionAccess
	var err error
	switch r.Method {
	case "GET":
		options, err = s.repository.SubscriptionAccess(id)
	case "PUT", "POST":
		var input struct {
			Enabled  *bool    `json:"enabled"`
			Networks []string `json:"networks"`
		}
		if readJSON(w, r, &input) != nil || input.Enabled == nil {
			problem(w, 400, "请提交启用状态和 IP 白名单")
			return true
		}
		options = config.SubscriptionAccess{Enabled: *input.Enabled, Networks: input.Networks}
		if r.Method == "PUT" {
			options, err = s.repository.SetSubscriptionAccess(id, options)
		} else {
			_, err = s.repository.SubscriptionAccess(id)
			if err == nil {
				options, _, err = config.PreviewSubscriptionAccess(options, "")
			}
		}
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	ip, source := s.subscriptionClientIP(r)
	_, allowed, _ := config.PreviewSubscriptionAccess(options, ip)
	respond(w, 200, map[string]any{"options": options, "clientIP": ip, "ipSource": source, "currentAllowed": allowed, "preview": r.Method == "POST"})
	return true
}
