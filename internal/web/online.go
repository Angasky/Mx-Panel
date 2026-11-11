package web

import (
	"context"
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"github.com/Angasky/dingzhi-ban/internal/subsource"
	"net/http"
	"net/netip"
	"time"
)

func (s *Server) onlineRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/traffic/online" && r.URL.Path != "/admin/api/traffic/online/city" && r.URL.Path != "/admin/api/traffic/online/enable" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.URL.Path == "/admin/api/traffic/online/enable" {
		if r.Method != "POST" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		var input struct {
			Binding   int    `json:"binding"`
			Token     string `json:"token"`
			Confirmed bool   `json:"confirmed"`
		}
		if readJSON(w, r, &input) != nil || !input.Confirmed {
			problem(w, 400, "需确认重启内核并启用在线统计")
			return true
		}
		c, e := s.subscriptionController()
		if e != nil {
			problem(w, 500, "订阅控制器不可用")
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		result, e := c.EnableOnline(ctx, r.Header.Get("X-Profile"), input.Binding, input.Token)
		if e != nil {
			problem(w, 400, e.Error())
		} else {
			respond(w, 200, result)
		}
		return true
	}

	if r.URL.Path == "/admin/api/traffic/online/city" {
		if r.Method != "POST" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		var input struct {
			IP        string `json:"ip"`
			Confirmed bool   `json:"confirmed"`
		}
		if readJSON(w, r, &input) != nil || !input.Confirmed {
			problem(w, 400, "需确认将 IP 发往城市查询服务")
			return true
		}
		ip, e := netip.ParseAddr(input.IP)
		if e != nil || !netguard.PublicAddress(ip) {
			problem(w, 400, "仅支持公网 IP 城市查询")
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
		defer cancel()
		body, e := subsource.NewClient().Fetch(ctx, "https://ipwho.is/"+ip.Unmap().String())
		var data struct {
			Success bool   `json:"success"`
			Country string `json:"country"`
			Region  string `json:"region"`
			City    string `json:"city"`
		}
		if e != nil || len(body) > 65536 || json.Unmarshal([]byte(body), &data) != nil || !data.Success {
			problem(w, 502, "城市查询服务暂不可用")
			return true
		}
		respond(w, 200, map[string]any{"country": data.Country, "region": data.Region, "city": data.City, "provider": "ipwho.is"})
		return true
	}
	if r.Method != "GET" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	c, e := s.subscriptionController()
	if e != nil {
		problem(w, 500, "订阅控制器不可用")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	result, e := c.Online(ctx, r.Header.Get("X-Profile"))
	if e != nil {
		problem(w, 400, e.Error())
	} else {
		respond(w, 200, result)
	}
	return true
}
