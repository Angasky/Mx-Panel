package web

import (
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
	"net/http"
)

func (s *Server) usageDisplayRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/subscription-usage-display" {
		return false
	}
	id := r.Header.Get("X-Profile")
	o, e := s.repository.UsageDisplay(id)
	if e != nil {
		problem(w, 400, e.Error())
		return true
	}
	switch r.Method {
	case "GET":
	case "POST", "PUT":
		var input struct {
			Options *struct {
				Enabled   *bool  `json:"enabled"`
				Used      string `json:"used"`
				Remaining string `json:"remaining"`
				Expiry    string `json:"expiry"`
			} `json:"options"`
			Revision string `json:"revision"`
		}
		if e := readJSON(w, r, &input); e != nil {
			problem(w, 400, e.Error())
			return true
		}
		if input.Options == nil || input.Options.Enabled == nil {
			problem(w, 400, "请提交完整的信息节点设置")
			return true
		}
		o = config.UsageDisplay{Enabled: *input.Options.Enabled, Used: input.Options.Used, Remaining: input.Options.Remaining, Expiry: input.Options.Expiry}
		if e := o.Validate(); e != nil {
			problem(w, 400, e.Error())
			return true
		}
		if r.Method == "PUT" {
			if e := s.repository.SetUsageDisplay(id, o, input.Revision); e != nil {
				code := 400
				if errors.Is(e, config.ErrUsageDisplayChanged) {
					code = 409
				}
				problem(w, code, e.Error())
				return true
			}
		}
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	// Fixed example; never read or change real quotas to preview a label.
	sample := config.Document{"configured": true, "used": int64(20 << 30), "total": int64(100 << 30), "remaining": int64(80 << 30), "expire": s.now().AddDate(0, 0, 7).Unix()}
	respond(w, 200, map[string]any{"options": o, "revision": o.Revision(), "sample": true, "names": subscriptions.UsageNodeNames(sample, s.now(), &o)})
	return true
}
