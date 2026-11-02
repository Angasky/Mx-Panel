package web

import (
	"errors"
	"net/http"
	"strings"

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
	allowed := map[string]bool{"/admin/api/groups": true, "/admin/api/rules": true, "/admin/api/dns": true}
	standard := allowed[path] && (method == "POST" || method == "PUT" || method == "DELETE")
	special := path == "/admin/api/raw" && method == "PUT" || (path == "/admin/api/rules/move" || path == "/admin/api/nodes/groups" || path == "/admin/api/nodes/bulk") && method == "POST"
	if !standard && !special {
		return false
	}
	var payload map[string]any
	if err := readJSON(w, r, &payload); err != nil || payload == nil {
		problem(w, 400, "请求 JSON 必须为对象")
		return true
	}
	var groups []string
	if path == "/admin/api/nodes/groups" {
		var err error
		groups, err = s.repository.GroupOptions(r.Header.Get("X-Profile"))
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
	}
	err := s.repository.Mutate(r.Header.Get("X-Profile"), func(doc config.Document) error {
		switch path {
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
		case "/admin/api/nodes/bulk":
			return config.DeleteManyNodes(doc, payload)
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
	username := strings.TrimSpace(input.NewUsername)
	if username == "" {
		username = auth.Username
	}
	password := input.NewPassword
	if password == "" {
		password = input.New
	}
	if len(username) > 64 || strings.ContainsAny(username, "\r\n\x00") || password != "" && (len(password) < 12 || len(password) > 256) {
		problem(w, 400, "账号无效，或新密码长度不在 12–256 之间")
		return
	}
	next := auth
	next.Username = username
	if password != "" {
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
	if auth.Hash != s.account.Hash || auth.Username != s.account.Username {
		problem(w, 409, "账号已被其他请求修改，请重新登录")
		return
	}
	err := storage.New(s.options.AuthFile).Update(func(doc map[string]any) error {
		if doc["hash"] != auth.Hash || doc["username"] != auth.Username {
			return errors.New("账号文件已变化")
		}
		doc["username"] = next.Username
		doc["salt"] = next.Salt
		doc["hash"] = next.Hash
		doc["iterations"] = next.Iterations
		return nil
	})
	if err != nil {
		problem(w, 500, "账号保存失败")
		return
	}
	s.account = next
	s.sessions = make(map[[32]byte]session)
	http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]any{"ok": true})
}
