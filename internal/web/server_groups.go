package web

import (
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/http"
)

func (s *Server) serverGroupsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/groups" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" && r.Method != "PUT" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器索引读取失败")
		return true
	}
	var change *remote.ServerGroupChange
	if r.Method == "PUT" {
		change = &remote.ServerGroupChange{}
		if e = readJSON(w, r, change); e != nil {
			problem(w, 400, "分组请求格式无效")
			return true
		}
	}
	result, e := m.ServerGroups(change)
	if e != nil {
		code := 400
		if change == nil {
			code = 500
		}
		if errors.Is(e, remote.ErrGroupConflict) {
			code = 409
		}
		problem(w, code, e.Error())
		return true
	}
	respond(w, 200, result)
	return true
}
