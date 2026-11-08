package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
	"github.com/Angasky/dingzhi-ban/internal/storage"
)

func (s *Server) editRoutes(w http.ResponseWriter, r *http.Request) bool {
	if s.remoteRoutes(w, r) {
		return true
	}
	path := r.URL.Path
	method := r.Method
	if path == "/admin/api/policy-templates" {
		var result config.Document
		var err error
		switch method {
		case "GET":
			query := r.URL.Query()
			result, err = s.repository.PolicyTemplates(r.Header.Get("X-Profile"), query.Get("id"), query.Get("source"))
		case "POST", "PUT", "DELETE":
			var payload config.Document
			if readJSON(w, r, &payload) != nil || payload == nil {
				problem(w, 400, "请求 JSON 必须为对象")
				return true
			}
			result, err = s.repository.SavePolicyTemplate(method, payload)
		default:
			w.Header().Set("Allow", "GET, POST, PUT, DELETE")
			problem(w, 405, "请求方法不支持")
			return true
		}
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, result)
		}
		return true
	}
	if method == "POST" && path == "/admin/api/failovers" {
		var payload config.Document
		if readJSON(w, r, &payload) != nil || payload == nil {
			problem(w, 400, "请提交主备组配置")
			return true
		}
		controller, err := s.subscriptionController()
		if err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			var result config.Document
			result, err = controller.CreateFailover(ctx, r.Header.Get("X-Profile"), payload)
			if err == nil {
				respond(w, 200, config.Document{"ok": true, "failover": result})
				return true
			}
		}
		problem(w, 400, err.Error())
		return true
	}
	if method == "DELETE" && (path == "/admin/api/server-chains" || path == "/admin/api/failovers") {
		var input struct {
			Name string `json:"name"`
		}
		if readJSON(w, r, &input) != nil {
			problem(w, 400, "请提交服务器链路名称")
			return true
		}
		controller, err := s.subscriptionController()
		if err == nil {
			var result config.Document
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			if path == "/admin/api/failovers" {
				result, err = controller.DeleteFailover(ctx, r.Header.Get("X-Profile"), input.Name)
			} else {
				result, err = controller.DeleteServerChain(ctx, r.Header.Get("X-Profile"), input.Name)
			}
			if err == nil {
				respond(w, 200, result)
				return true
			}
		}
		problem(w, 400, err.Error())
		return true
	}
	if method == "GET" && (path == "/admin/api/failovers" || path == "/admin/api/server-chains") {
		state, err := s.repository.State(r.Header.Get("X-Profile"))
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		key, responseKey := "failovers", "failovers"
		if path == "/admin/api/server-chains" {
			key, responseKey = "serverChains", "chains"
		}
		values := []any{}
		if state[key] != nil {
			var ok bool
			values, ok = state[key].([]any)
			if !ok {
				problem(w, 400, "链路记录格式无效")
				return true
			}
		}
		if key == "failovers" {
			if drafts, ok := state["failoverDrafts"].([]any); ok {
				values = append(values, drafts...)
			}
		}
		respond(w, 200, map[string]any{responseKey: values})
		return true
	}
	if path == "/admin/api/backups" && method == "GET" {
		values, err := s.repository.Backups(r.Header.Get("X-Profile"))
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"backups": values})
		}
		return true
	}
	if path == "/admin/api/backups/restore" && method == "POST" {
		var payload struct{ Name string }
		if err := readJSON(w, r, &payload); err != nil {
			problem(w, 400, err.Error())
			return true
		}
		if err := s.repository.Restore(r.Header.Get("X-Profile"), payload.Name); err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"ok": true})
		}
		return true
	}
	if (path == "/admin/api/account" || path == "/admin/api/password") && method == "POST" {
		s.changeAccount(w, r)
		return true
	}
	if path == "/admin/api/profiles" && (method == "POST" || method == "PUT" || method == "DELETE") {
		var payload map[string]any
		if err := readJSON(w, r, &payload); err != nil || payload == nil {
			problem(w, 400, "请求 JSON 必须为对象")
			return true
		}
		var profile map[string]any
		var err error
		switch method {
		case "POST":
			profile, err = s.repository.CreateProfile(payload)
		case "PUT":
			profile, err = s.repository.UpdateProfile(payload)
		default:
			id, _ := payload["id"].(string)
			err = s.repository.DeleteProfile(id)
		}
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"ok": true, "profile": profile})
		}
		return true
	}
	if path == "/admin/api/nodes/group-options" && method == "GET" {
		groups, err := s.repository.GroupOptions(r.Header.Get("X-Profile"))
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		respond(w, 200, map[string]any{"groups": groups})
		return true
	}
	if path == "/admin/api/nodes/bulk" {
		if method != "DELETE" && method != "POST" {
			w.Header().Set("Allow", "DELETE, POST")
			problem(w, 405, "请求方法不支持")
			return true
		}
		var payload config.Document
		if readJSON(w, r, &payload) != nil || payload == nil {
			problem(w, 400, "请求 JSON 必须为对象")
			return true
		}
		deleted := []string{}
		err := s.repository.Mutate(r.Header.Get("X-Profile"), func(doc config.Document) error {
			before, _ := doc["proxies"].([]any)
			if err := config.DeleteManyNodes(doc, payload); err != nil {
				return err
			}
			remaining := map[string]bool{}
			after, _ := doc["proxies"].([]any)
			for _, item := range after {
				remaining[item.(map[string]any)["name"].(string)] = true
			}
			for _, item := range before {
				name := item.(map[string]any)["name"].(string)
				if !remaining[name] {
					deleted = append(deleted, name)
				}
			}
			return nil
		})
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"ok": true, "deleted": len(deleted), "names": deleted})
		}
		return true
	}
	allowed := map[string]bool{"/admin/api/groups": true, "/admin/api/rules": true, "/admin/api/dns": true}
	standard := allowed[path] && (method == "POST" || method == "PUT" || method == "DELETE")
	special := path == "/admin/api/chains" && (method == "POST" || method == "PUT") || path == "/admin/api/raw" && method == "PUT" || (path == "/admin/api/rules/move" || path == "/admin/api/nodes/groups") && method == "POST"
	if !standard && !special {
		return false
	}
	var payload map[string]any
	if err := readJSON(w, r, &payload); err != nil || payload == nil {
		problem(w, 400, "请求 JSON 必须为对象")
		return true
	}
	if path == "/admin/api/chains" && payload["mode"] == "server" && method == "POST" {
		controller, err := s.subscriptionController()
		if err == nil {
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
			defer cancel()
			var result config.Document
			result, err = controller.CreateServerChain(ctx, r.Header.Get("X-Profile"), payload)
			if err == nil {
				respond(w, 200, result)
				return true
			}
		}
		problem(w, 400, err.Error())
		return true
	}
	var groups []string
	if path == "/admin/api/nodes/groups" || path == "/admin/api/chains" {
		var err error
		groups, err = s.repository.GroupOptions(r.Header.Get("X-Profile"))
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
	}
	err := s.repository.Mutate(r.Header.Get("X-Profile"), func(doc config.Document) error {
		switch path {
		case "/admin/api/chains":
			return config.EditChain(doc, method, payload, groups)
		case "/admin/api/groups":
			return config.EditGroup(doc, method, payload)
		case "/admin/api/rules":
			return config.EditRule(doc, method, payload)
		case "/admin/api/dns":
			return config.EditDNS(doc, method, payload)
		case "/admin/api/raw":
			return config.ReplaceRaw(doc, payload)
		case "/admin/api/nodes/groups":
			return config.EditMembership(doc, payload, groups)
		default:
			return config.MoveRule(doc, payload)
		}
	})
	if err != nil {
		problem(w, 400, err.Error())
	} else {
		respond(w, 200, map[string]any{"ok": true})
	}
	return true
}

func (s *Server) changeAccount(w http.ResponseWriter, r *http.Request) {
	s.userAdminMu.Lock()
	defer s.userAdminMu.Unlock()
	var input struct{ Username, Current, NewUsername, NewPassword, New string }
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return
	}
	s.mu.Lock()
	auth := s.account
	s.mu.Unlock()
	if input.Username == "" {
		input.Username = auth.Username
	}
	if !legacycrypto.VerifyPassword(input.Current, auth.Salt, auth.Hash, auth.Iterations) || input.Username != auth.Username {
		problem(w, 403, "当前账号或密码错误")
		return
	}
	username := input.NewUsername
	if username == "" {
		username = auth.Username
	}
	username = strings.TrimSpace(username)
	password := input.NewPassword
	if password == "" {
		password = input.New
	}
	if utf8.RuneCountInString(username) < 3 || utf8.RuneCountInString(username) > 64 || strings.ContainsAny(username, ":\x00") || strings.ContainsFunc(username, unicode.IsSpace) || password != "" && (utf8.RuneCountInString(password) < 12 || utf8.RuneCountInString(password) > 256) {
		problem(w, 400, "账号无效，或新密码长度不在 12–256 之间")
		return
	}
	users, userErr := s.users()
	if userErr != nil {
		problem(w, 500, "用户数据读取失败")
		return
	}
	for _, u := range users {
		if strings.EqualFold(u.Username, username) {
			problem(w, 400, "用户名与普通用户重复")
			return
		}
	}
	next := auth
	next.Username = username
	if password != "" || auth.Iterations < 600000 {
		if password == "" {
			password = input.Current
		}
		salt, digest, err := legacycrypto.NewPassword(password)
		if err != nil {
			problem(w, 500, "密码更新失败")
			return
		}
		next.Salt = salt
		next.Hash = digest
		next.Iterations = 600000
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if auth != s.account {
		problem(w, 409, "账号已被其他请求修改，请重新登录")
		return
	}
	err := storage.New(s.options.AuthFile).Update(func(doc map[string]any) error {
		raw, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		var disk account
		if err := json.Unmarshal(raw, &disk); err != nil {
			return err
		}
		if disk.Iterations == 0 {
			disk.Iterations = 240000
		}
		if disk != auth {
			return errors.New("账号文件已变化")
		}
		doc["username"] = next.Username
		doc["salt"] = next.Salt
		doc["hash"] = next.Hash
		doc["iterations"] = next.Iterations
		doc["goSessions"] = encodeSessions(next, map[[32]byte]session{})
		doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(next), Entries: map[string]failure{}}
		return nil
	})
	if err != nil {
		problem(w, 500, "账号保存失败")
		return
	}
	s.account = next
	s.sessions = make(map[[32]byte]session)
	s.failures = make(map[string]failure)
	http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]any{"ok": true})
}
