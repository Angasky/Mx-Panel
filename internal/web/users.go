package web

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
	"github.com/Angasky/dingzhi-ban/internal/storage"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

type panelUser struct {
	ID         string             `json:"id"`
	Username   string             `json:"username"`
	Salt       string             `json:"salt"`
	Hash       string             `json:"hash"`
	Iterations int                `json:"iterations"`
	Enabled    bool               `json:"enabled"`
	Profiles   []string           `json:"profiles"`
	Sessions   map[string]session `json:"sessions"`
}

func (s *Server) userStore() *storage.Store {
	return storage.New(filepath.Join(s.options.Root, "panel-users.json"))
}
func (s *Server) updateUsers(change func(map[string]any) error) error {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	path := filepath.Join(s.options.Root, "panel-users.json")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		_, err = f.WriteString("{\"users\":[]}\n")
		closeErr := f.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
	} else if !os.IsExist(err) {
		return err
	}
	return s.userStore().Update(change)
}
func decodeUsers(doc map[string]any) ([]panelUser, error) {
	if doc["users"] == nil {
		return []panelUser{}, nil
	}
	raw, err := json.Marshal(doc["users"])
	if err != nil {
		return nil, err
	}
	var users []panelUser
	err = json.Unmarshal(raw, &users)
	if err != nil {
		return nil, err
	}
	ids, names := map[string]bool{}, map[string]bool{}
	if len(users) > 1000 {
		return nil, errors.New("用户数据超出限制")
	}
	for _, u := range users {
		salt, se := hex.DecodeString(u.Salt)
		hash, he := hex.DecodeString(u.Hash)
		name := strings.ToLower(u.Username)
		if u.ID == "" || ids[u.ID] || names[name] || !validUserCredentials(u.Username, "", false) || se != nil || he != nil || len(salt) != 16 || len(hash) != 32 || u.Iterations < 100000 || u.Iterations > 2000000 || len(u.Sessions) > sessionLimit {
			return nil, errors.New("用户数据损坏")
		}
		ids[u.ID] = true
		names[name] = true
		for key, entry := range u.Sessions {
			digest, e := hex.DecodeString(key)
			if e != nil || len(digest) != 32 || entry.Created.IsZero() || !entry.Expires.After(entry.Created) || entry.Expires.Sub(entry.Created) > sessionTTL {
				return nil, errors.New("用户会话损坏")
			}
		}
	}
	return users, nil
}
func (s *Server) users() ([]panelUser, error) {
	s.userMu.Lock()
	defer s.userMu.Unlock()
	doc, err := s.userStore().Read()
	if os.IsNotExist(err) {
		return []panelUser{}, nil
	}
	if err != nil {
		return nil, err
	}
	return decodeUsers(doc)
}
func userView(u panelUser) map[string]any {
	return map[string]any{"id": u.ID, "username": u.Username, "enabled": u.Enabled, "profiles": u.Profiles, "role": "user"}
}
func userDigest(r *http.Request) string {
	h := sha256.Sum256([]byte(requestSessionToken(r)))
	return hex.EncodeToString(h[:])
}
func (s *Server) member(r *http.Request) (panelUser, bool) {
	token := requestSessionToken(r)
	if token == "" || len(token) > 256 {
		return panelUser{}, false
	}
	users, err := s.users()
	if err != nil {
		return panelUser{}, false
	}
	digest := userDigest(r)
	for _, u := range users {
		if entry, ok := u.Sessions[digest]; ok && u.Enabled && s.now().Before(entry.Expires) {
			return u, true
		}
	}
	return panelUser{}, false
}

// Called after the shared login limiter has reserved an attempt/hash slot.
func (s *Server) memberLogin(w http.ResponseWriter, r *http.Request, username, password string, keys []string) {
	defer func() { <-s.hashSlots }()
	users, err := s.users()
	if err != nil {
		problem(w, 500, "用户记录读取失败")
		return
	}
	var selected panelUser
	for _, u := range users {
		if u.Username == username {
			selected = u
			break
		}
	}
	s.mu.Lock()
	dummy := s.account
	s.mu.Unlock()
	salt, hash, iterations := selected.Salt, selected.Hash, selected.Iterations
	if selected.ID == "" {
		salt, hash, iterations = dummy.Salt, dummy.Hash, dummy.Iterations
	}
	valid := legacycrypto.VerifyPassword(password, salt, hash, iterations)
	if !valid || selected.ID == "" || !selected.Enabled {
		problem(w, 403, "账号或密码错误")
		return
	}
	random := make([]byte, 32)
	if _, err = rand.Read(random); err != nil {
		problem(w, 500, "会话创建失败")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	digest := sha256.Sum256([]byte(token))
	key := hex.EncodeToString(digest[:])
	err = s.updateUsers(func(doc map[string]any) error {
		current, e := decodeUsers(doc)
		if e != nil {
			return e
		}
		for i := range current {
			u := &current[i]
			if u.ID != selected.ID {
				continue
			}
			if !u.Enabled || u.Hash != selected.Hash || u.Username != selected.Username {
				return errors.New("账号已变更")
			}
			if u.Sessions == nil {
				u.Sessions = map[string]session{}
			}
			for k, v := range u.Sessions {
				if !s.now().Before(v.Expires) {
					delete(u.Sessions, k)
				}
			}
			for len(u.Sessions) >= sessionLimit {
				old := ""
				for k, v := range u.Sessions {
					if old == "" || v.Created.Before(u.Sessions[old].Created) {
						old = k
					}
				}
				delete(u.Sessions, old)
			}
			now := s.now()
			u.Sessions[key] = session{Created: now, Expires: now.Add(sessionTTL)}
			doc["users"] = current
			return nil
		}
		return errors.New("账号不存在")
	})
	if err != nil {
		problem(w, 500, "登录会话保存失败")
		return
	}
	s.mu.Lock()
	next := copyLoginFailures(s.failures, s.now())
	for _, k := range keys {
		delete(next, k)
	}
	err = s.persistLoginFailures(next)
	s.mu.Unlock()
	if err != nil {
		problem(w, 500, "登录状态保存失败")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Value: token, Path: "/admin", MaxAge: 12 * 3600, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]any{"ok": true, "token": token, "role": "user"})
}
func validUserCredentials(username, password string, requirePassword bool) bool {
	return utf8.ValidString(username) && utf8.RuneCountInString(username) >= 3 && utf8.RuneCountInString(username) <= 64 && strings.IndexFunc(username, unicode.IsSpace) < 0 && !strings.ContainsAny(username, ":\x00") && (!requirePassword && password == "" || utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && len(password) <= 1024 && !strings.ContainsAny(password, "\r\n\x00"))
}
func (s *Server) userAdminRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/users" {
		return false
	}
	if r.Method == "GET" {
		users, err := s.users()
		if err != nil {
			problem(w, 500, "读取用户失败")
			return true
		}
		views := []any{}
		for _, u := range users {
			views = append(views, userView(u))
		}
		respond(w, 200, map[string]any{"users": views})
		return true
	}
	if r.Method != "POST" && r.Method != "PUT" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.userAdminMu.Lock()
	defer s.userAdminMu.Unlock()
	var input struct {
		ID, Username, Password string
		Enabled                bool
		Profiles               []string
	}
	if readJSON(w, r, &input) != nil {
		problem(w, 400, "请求格式无效")
		return true
	}
	if r.Method != "DELETE" {
		if !validUserCredentials(input.Username, input.Password, r.Method == "POST") {
			problem(w, 400, "用户名需 3–64 字符且无空格；密码至少 12 字符")
			return true
		}
		s.mu.Lock()
		admin := s.account.Username
		s.mu.Unlock()
		if strings.EqualFold(input.Username, admin) {
			problem(w, 400, "用户名与管理员重复")
			return true
		}
		profiles, err := s.repository.Profiles()
		if err != nil {
			problem(w, 400, "读取订阅失败")
			return true
		}
		allowed := map[string]bool{}
		for _, p := range profiles {
			allowed[p["id"].(string)] = true
		}
		seen := map[string]bool{}
		for _, id := range input.Profiles {
			if !allowed[id] || seen[id] {
				problem(w, 400, "订阅不存在或重复")
				return true
			}
			seen[id] = true
		}
	}
	var salt, hash string
	var err error
	if input.Password != "" {
		salt, hash, err = legacycrypto.NewPassword(input.Password)
		if err != nil {
			problem(w, 500, "密码处理失败")
			return true
		}
	}
	if r.Method == "POST" {
		raw := make([]byte, 16)
		if _, err = rand.Read(raw); err != nil {
			problem(w, 500, "用户创建失败")
			return true
		}
		input.ID = hex.EncodeToString(raw)
	}
	err = s.updateUsers(func(doc map[string]any) error {
		users, e := decodeUsers(doc)
		if e != nil {
			return e
		}
		found := -1
		for i, u := range users {
			if u.ID == input.ID {
				found = i
			}
			if r.Method != "DELETE" && u.ID != input.ID && strings.EqualFold(u.Username, input.Username) {
				return errors.New("用户名已存在")
			}
		}
		if r.Method == "POST" {
			if len(users) >= 1000 {
				return errors.New("最多支持 1000 个用户")
			}
			users = append(users, panelUser{ID: input.ID})
			found = len(users) - 1
		} else if found < 0 {
			return errors.New("用户不存在")
		}
		if r.Method == "DELETE" {
			users = append(users[:found], users[found+1:]...)
		} else {
			u := &users[found]
			u.Username = input.Username
			u.Enabled = input.Enabled
			u.Profiles = input.Profiles
			u.Sessions = map[string]session{}
			if hash != "" {
				u.Salt = salt
				u.Hash = hash
				u.Iterations = 600000
			}
		}
		doc["users"] = users
		return nil
	})
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	respond(w, 200, map[string]any{"ok": true, "id": input.ID})
	return true
}

// Members never reach administrator routes, even with forged headers or IDs.
func (s *Server) memberRoutes(w http.ResponseWriter, r *http.Request, u panelUser) {
	switch {
	case r.URL.Path == "/admin/api/account" && r.Method == "GET":
		respond(w, 200, userView(u))
	case r.URL.Path == "/admin/api/logout" && r.Method == "POST":
		err := s.updateUsers(func(doc map[string]any) error {
			users, e := decodeUsers(doc)
			if e != nil {
				return e
			}
			for i := range users {
				delete(users[i].Sessions, userDigest(r))
			}
			doc["users"] = users
			return nil
		})
		if err != nil {
			problem(w, 500, "退出失败，请重试")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]any{"ok": true})
	case r.URL.Path == "/admin/api/portal" && r.Method == "GET":
		profiles, err := s.repository.Profiles()
		if err != nil {
			problem(w, 500, "订阅读取失败")
			return
		}
		allowed := map[string]bool{}
		for _, id := range u.Profiles {
			allowed[id] = true
		}
		result := []any{}
		for _, p := range profiles {
			id, _ := p["id"].(string)
			if !allowed[id] {
				continue
			}
			source, e := s.repository.ConversionSource(id, s.now())
			if e != nil {
				result = append(result, map[string]any{"id": id, "name": p["name"], "unavailable": true})
				continue
			}
			// Deliberate whitelist: never expose filesystem paths, remote credentials or managed bindings.
			traffic := map[string]any{}
			for _, key := range []string{"configured", "upload", "download", "used", "total", "remaining", "expire", "expired", "exhausted"} {
				traffic[key] = source.Traffic[key]
			}
			result = append(result, map[string]any{"id": id, "name": source.Name, "url": "/sub/" + source.Slug, "traffic": traffic, "formats": subscriptions.ConversionReport(source, s.now())})
		}
		respond(w, 200, map[string]any{"profiles": result})
	default:
		problem(w, 403, "普通用户无权执行此操作")
	}
}
