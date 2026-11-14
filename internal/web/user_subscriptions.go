package web

import (
	"net/http"

	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

// An administrator convenience view, not a user impersonation or a new token.
func (s *Server) userSubscriptionsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/users/subscriptions" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	users, err := s.users()
	if err != nil {
		problem(w, 500, "读取用户失败")
		return true
	}
	var selected *panelUser
	for _, u := range users {
		if u.ID == r.URL.Query().Get("id") {
			selected = &u
			break
		}
	}
	if selected == nil {
		problem(w, 404, "用户不存在，请刷新列表")
		return true
	}
	if !selected.Enabled {
		problem(w, 409, "用户已禁用，不展示订阅地址")
		return true
	}
	profiles, err := s.repository.Profiles()
	if err != nil {
		problem(w, 500, "订阅读取失败")
		return true
	}
	allowed := map[string]bool{}
	for _, id := range selected.Profiles {
		allowed[id] = true
	}
	rows := []map[string]any{}
	requested := r.URL.Query().Get("profile")
	found := false
	for _, p := range profiles {
		id, _ := p["id"].(string)
		if !allowed[id] {
			continue
		}
		rows = append(rows, map[string]any{"id": id, "name": p["name"]})
		if id == requested {
			found = true
		}
	}
	result := map[string]any{"user": map[string]any{"id": selected.ID, "username": selected.Username}, "profiles": rows}
	if requested != "" {
		if !found {
			problem(w, 403, "用户未获授权访问此订阅，或订阅已删除")
			return true
		}
		now := s.now()
		source, e := s.repository.ConversionSource(requested, now)
		if e != nil {
			problem(w, 409, "订阅暂不可用，请检查配置")
			return true
		}
		result["subscription"] = map[string]any{"id": requested, "name": source.Name, "url": "/sub/" + source.Slug, "formats": subscriptions.ConversionReport(source, now)}
	}
	respond(w, 200, result)
	return true
}
