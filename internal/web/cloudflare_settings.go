package web

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/http"
	"net/mail"
	"strconv"
	"strings"
	"time"
)

func cfClient(key, email string) cfDNSClient {
	return cfDNSClient{client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: "https://api.cloudflare.com/client/v4", key: key, email: email}
}
func (c cfDNSClient) zones(ctx context.Context) ([]remote.CFZone, error) {
	all := []remote.CFZone{}
	seen := map[string]bool{}
	for page := 1; page <= 100; page++ {
		var rows []remote.CFZone
		if e := c.call(ctx, "GET", "/zones?per_page=50&page="+strconv.Itoa(page), nil, &rows); e != nil {
			return nil, e
		}
		for _, z := range rows {
			if !cfID.MatchString(z.ID) || cfDomain(z.Name) == "" {
				return nil, errors.New("CF 返回了无效的域名或区域 ID，未覆盖原列表")
			}
			if seen[z.ID] {
				return nil, errors.New("CF 返回了重复的域名区域分页，请重新同步；未覆盖原列表")
			}
			seen[z.ID] = true
			all = append(all, z)
		}
		if len(rows) < 50 {
			return all, nil
		}
	}
	return nil, errors.New("CF 域名数量超过同步上限，未保存不完整列表")
}
func cfPublic(c remote.CFSettings) map[string]any {
	return map[string]any{"configured": c.Secret != "", "email": c.Email, "zones": c.Zones, "revision": c.Revision}
}
func (s *Server) cloudflareSettingsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/cloudflare/settings" && r.URL.Path != "/admin/api/cloudflare/zones" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	c, e := m.CloudflareSettings()
	if e != nil {
		problem(w, 500, "CF 设置读取失败")
		return true
	}
	if r.Method == "GET" {
		respond(w, 200, cfPublic(c))
		return true
	}
	var in struct {
		Key      string `json:"key"`
		Email    string `json:"email"`
		Revision string `json:"revision"`
	}
	if r.Method != "PUT" && r.Method != "POST" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	if readJSON(w, r, &in) != nil || in.Revision != c.Revision {
		problem(w, 409, "CF 设置已变化或参数无效，请刷新")
		return true
	}
	if r.URL.Path == "/admin/api/cloudflare/zones" {
		if r.Method != "POST" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		key, e := m.CloudflareKey(c)
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
		defer cancel()
		zones, e := cfClient(key, c.Email).zones(ctx)
		if e != nil {
			problem(w, 400, e.Error())
			return true
		}
		c, e = m.SaveCloudflare(c.Revision, "", "", zones, false)
		if e != nil {
			problem(w, 409, e.Error())
		} else {
			respond(w, 200, cfPublic(c))
		}
		return true
	}
	if r.Method == "DELETE" {
		c, e = m.SaveCloudflare(c.Revision, "", "", nil, true)
	} else if r.Method == "PUT" {
		key, email := strings.TrimSpace(in.Key), strings.TrimSpace(in.Email)
		if len(key) < 16 || len(key) > 512 || strings.ContainsAny(key, "\r\n\t ") {
			problem(w, 400, "请输入有效 CF 凭据")
			return true
		}
		if email != "" {
			a, err := mail.ParseAddress(email)
			if err != nil || a.Address != email {
				problem(w, 400, "邮箱无效")
				return true
			}
		}
		c, e = m.SaveCloudflare(c.Revision, key, email, nil, false)
	} else {
		problem(w, 405, "请求方法不支持")
		return true
	}
	if e != nil {
		problem(w, 409, e.Error())
	} else {
		respond(w, 200, cfPublic(c))
	}
	return true
}
