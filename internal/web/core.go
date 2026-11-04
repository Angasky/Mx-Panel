package web

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) coreRoutes(w http.ResponseWriter, r *http.Request) bool {
	scoped := r.URL.Path == "/admin/api/servers/core/inbound"
	if !scoped && r.URL.Path != "/admin/api/servers/core" {
		return false
	}
	if scoped && r.Method != "PUT" {
		w.Header().Set("Allow", "PUT")
		problem(w, 405, "请求方法不支持")
		return true
	}
	if r.Method != "GET" && r.Method != "PUT" {
		w.Header().Set("Allow", "GET, PUT")
		problem(w, 405, "请求方法不支持")
		return true
	}
	id, version := r.URL.Query().Get("id"), ""
	var next map[string]any
	var operation, tag string
	if r.Method == "PUT" {
		var input struct {
			ServerID  string         `json:"serverId"`
			Version   string         `json:"version"`
			Config    map[string]any `json:"config"`
			Operation string         `json:"operation"`
			Tag       string         `json:"tag"`
		}
		if readJSON(w, r, &input) != nil || input.ServerID == "" || len(input.Version) != 64 || input.Config == nil {
			problem(w, 400, "请提交服务器、原配置版本和 JSON 配置对象")
			return true
		}
		id, version, next = input.ServerID, input.Version, input.Config
		operation, tag = input.Operation, input.Tag
		profiles, err := s.repository.ServerProfiles(id)
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		for _, profile := range profiles {
			state, err := s.repository.State(profile)
			if err != nil {
				problem(w, 400, err.Error())
				return true
			}
			bindings, _ := state["remoteNodes"].([]any)
			for _, v := range bindings {
				binding, ok := v.(map[string]any)
				if !ok {
					problem(w, 400, "订阅绑定记录无效")
					return true
				}
				if binding["serverId"] == id && (binding["status"] == "active" || binding["status"] == "provisioning" || binding["inboundDeletePending"] != nil) {
					message := "服务器存在活动或待核对的订阅用户，禁止整份配置覆盖"
					if scoped {
						message = "服务器存在活动或待核对的订阅用户，暂时禁止修改独立内核配置"
					}
					problem(w, 400, message)
					return true
				}
			}
		}
	}
	if id == "" {
		problem(w, 400, "请选择服务器")
		return true
	}
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	var result map[string]any
	if scoped {
		result, err = manager.EditCoreInbound(ctx, id, version, operation, tag, next)
	} else {
		result, err = manager.CoreConfig(ctx, id, version, next)
	}
	if err != nil {
		problem(w, 400, err.Error())
	} else {
		respond(w, 200, result)
	}
	return true
}
