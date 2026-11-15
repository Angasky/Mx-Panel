package web

import (
	"encoding/base64"
	"net/http"
	"net/url"

	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
	qrcode "github.com/skip2/go-qrcode"
)

// Resolve an authorized profile on the server instead of accepting arbitrary
// subscription URLs, tokens or user IDs from the browser.
func (s *Server) memberSubscriptionQR(w http.ResponseWriter, r *http.Request, u panelUser) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return
	}
	var in struct {
		Profile string `json:"profile"`
		Format  string `json:"format"`
	}
	if readJSON(w, r, &in) != nil || in.Profile == "" || !subscriptions.ValidClientChoice(in.Format) {
		problem(w, 400, "请选择订阅和客户端格式")
		return
	}
	allowed := false
	for _, id := range u.Profiles {
		if id == in.Profile {
			allowed = true
			break
		}
	}
	if !allowed {
		problem(w, 403, "无权访问此订阅")
		return
	}
	source, err := s.repository.ConversionSource(in.Profile, s.now())
	if err != nil {
		problem(w, 409, "订阅暂不可用，请刷新后重试")
		return
	}
	path := "/sub/" + url.PathEscape(source.Slug)
	name := "Clash / Mihomo"
	if in.Format != "clash" {
		available := false
		for _, f := range subscriptions.ConversionReport(source, s.now()) {
			if f["id"] == in.Format && f["available"] == true {
				path = f["url"].(string)
				name = f["name"].(string)
				available = true
				break
			}
		}
		if !available {
			problem(w, 409, "此订阅当前无法导出所选格式，请刷新后选择其他格式")
			return
		}
	}
	s.siteInfoMu.Lock()
	site, err := s.readSiteInfo()
	s.siteInfoMu.Unlock()
	if err != nil {
		problem(w, 503, "订阅域名设置暂不可用")
		return
	}
	origin := site.SubscriptionOrigin
	if origin == "" {
		origin = r.Header.Get("Origin")
		if !s.sameOrigin(r) {
			problem(w, 403, "请求来源无效")
			return
		}
	}
	address := origin + path
	png, err := qrcode.Encode(address, qrcode.Medium, 320)
	if err != nil {
		problem(w, 400, "订阅地址超过二维码编码范围")
		return
	}
	respond(w, 200, map[string]any{"name": source.Name, "format": in.Format, "client": name, "url": address, "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png)})
}
