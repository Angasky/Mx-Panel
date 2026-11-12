package web

import (
	"github.com/Angasky/dingzhi-ban/internal/config"
	"net/http"
)

func (s *Server) clientOptionsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/client-options" {
		return false
	}
	id := r.Header.Get("X-Profile")
	switch r.Method {
	case "GET":
	case "PUT":
		var input struct {
			WebRTC         *bool `json:"webRTC"`
			DNSProtection  *bool `json:"dnsProtection"`
			DomesticRealIP *bool `json:"domesticRealIP"`
			IPv6           *bool `json:"ipv6"`
			BasicAds       *bool `json:"basicAds"`
			StrongAds      *bool `json:"strongAds"`
			XrayExport     *bool `json:"xrayExport"`
			SingBoxExport  *bool `json:"singBoxExport"`
		}
		if readJSON(w, r, &input) != nil || input.WebRTC == nil || input.DNSProtection == nil || input.DomesticRealIP == nil || input.IPv6 == nil || input.BasicAds == nil || input.StrongAds == nil || input.XrayExport == nil || input.SingBoxExport == nil {
			problem(w, 400, "请提交完整的开关设置")
			return true
		}
		o := config.ClientOptions{WebRTC: *input.WebRTC, DNSProtection: *input.DNSProtection, DomesticRealIP: *input.DomesticRealIP, IPv6: *input.IPv6, BasicAds: *input.BasicAds, StrongAds: *input.StrongAds, XrayExport: *input.XrayExport, SingBoxExport: *input.SingBoxExport}
		if e := s.repository.SetClientOptions(id, &o); e != nil {
			problem(w, 400, e.Error())
			return true
		}
	case "DELETE":
		if e := s.repository.SetClientOptions(id, nil); e != nil {
			problem(w, 400, e.Error())
			return true
		}
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	options, configured, e := s.repository.ClientOptions(id)
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	respond(w, 200, map[string]any{"options": options, "configured": configured})
	return true
}
