// Package web contains the native Go management HTTP service.
package web

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

type Options struct {
	Root, AuthFile                       string
	TrustLoopbackProxy, LocalDevelopment bool
}
type account struct {
	Username, Salt, Hash string
	Iterations           int
}
type session struct{ Expires, Created time.Time }
type failure struct {
	Count int
	Since time.Time
}
type Server struct {
	options    Options
	account    account
	mu         sync.Mutex
	sessions   map[[32]byte]session
	failures   map[string]failure
	hashSlots  chan struct{}
	now        func() time.Time
	repository *config.Repository
}

func New(options Options) (*Server, error) {
	data, err := os.ReadFile(options.AuthFile)
	if err != nil {
		return nil, err
	}
	var auth account
	if err = json.Unmarshal(data, &auth); err != nil {
		return nil, err
	}
	if auth.Iterations == 0 {
		auth.Iterations = 240000
	}
	if auth.Username == "" || len(auth.Salt) != 32 || len(auth.Hash) != 64 || auth.Iterations < 100000 || auth.Iterations > 2000000 {
		return nil, errors.New("invalid administrator credential file")
	}
	return &Server{options: options, account: auth, sessions: make(map[[32]byte]session), failures: make(map[string]failure), hashSlots: make(chan struct{}, 2), now: time.Now, repository: &config.Repository{Root: options.Root}}, nil
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func problem(w http.ResponseWriter, status int, message string) {
	respond(w, status, map[string]any{"error": message})
}
func (s *Server) secure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback() && (s.options.LocalDevelopment || s.options.TrustLoopbackProxy && r.Header.Get("X-Forwarded-Proto") == "https")
}
func (s *Server) sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	value := r.Header.Get("Origin")
	if value == "" {
		return false
	}
	origin, err := url.Parse(value)
	if err != nil {
		return false
	}
	scheme := "https"
	if s.options.LocalDevelopment && r.TLS == nil {
		scheme = "http"
	}
	return origin.Scheme == scheme && strings.EqualFold(origin.Host, r.Host) && origin.User == nil && origin.Path == "" && origin.RawQuery == "" && origin.Fragment == ""
}
func readJSON(w http.ResponseWriter, r *http.Request, value any) error {
	if strings.Split(r.Header.Get("Content-Type"), ";")[0] != "application/json" {
		return errors.New("请求必须为 application/json")
	}
	reader := http.MaxBytesReader(w, r.Body, 2<<20)
	defer reader.Close()
	decoder := json.NewDecoder(reader)
	decoder.UseNumber()
	if err := decoder.Decode(value); err != nil {
		return errors.New("请求 JSON 无效或超过大小限制")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("请求包含多余 JSON 数据")
	}
	return nil
}
func (s *Server) authorized(r *http.Request) bool {
	token := ""
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		token = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	}
	if token == "" {
		if cookie, err := r.Cookie("mxioc_session"); err == nil {
			token = cookie.Value
		}
	}
	if token == "" || len(token) > 256 {
		return false
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.sessions[key]
	if !ok {
		return false
	}
	if !s.now().Before(value.Expires) {
		delete(s.sessions, key)
		return false
	}
	return true
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.URL.Path == "/healthz" && (r.Method == "GET" || r.Method == "HEAD") {
		respond(w, 200, map[string]any{"ok": true, "runtime": "go"})
		return
	}
	if r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
		if r.Method != "GET" && r.Method != "HEAD" {
			problem(w, 405, "请求方法不支持")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		http.ServeFile(w, r, filepath.Join(s.options.Root, "index.html"))
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/admin/api/") {
		problem(w, 404, "接口不存在")
		return
	}
	if !s.secure(r) {
		problem(w, 426, "管理后台必须通过 HTTPS 访问")
		return
	}
	if r.Method != "GET" && r.Method != "HEAD" && !s.sameOrigin(r) {
		problem(w, 403, "请求来源校验失败，请刷新页面后重试")
		return
	}
	if r.URL.Path == "/admin/api/login" && r.Method == "POST" {
		s.login(w, r)
		return
	}
	if !s.authorized(r) {
		problem(w, 401, "请重新登录")
		return
	}
	if r.URL.Path == "/admin/api/logout" && r.Method == "POST" {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token == "" {
			if c, e := r.Cookie("mxioc_session"); e == nil {
				token = c.Value
			}
		}
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(token)))
		s.mu.Unlock()
		http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]any{"ok": true})
		return
	}
	if r.URL.Path == "/admin/api/account" && r.Method == "GET" {
		respond(w, 200, map[string]any{"username": s.account.Username})
		return
	}
	if r.Method == "GET" {
		id := r.Header.Get("X-Profile")
		switch r.URL.Path {
		case "/admin/api/profiles":
			profiles, err := s.repository.Profiles()
			if err != nil {
				problem(w, 400, err.Error())
				return
			}
			respond(w, 200, map[string]any{"profiles": profiles})
			return
		case "/admin/api/snapshot":
			value, err := s.repository.Snapshot(id)
			if err != nil {
				problem(w, 400, err.Error())
				return
			}
			respond(w, 200, value)
			return
		case "/admin/api/raw":
			value, err := s.repository.Raw(id)
			if err != nil {
				problem(w, 400, err.Error())
				return
			}
			respond(w, 200, map[string]any{"yaml": value})
			return
		}
	}
	if r.URL.Path == "/admin/api/nodes/validate" && r.Method == "POST" {
		var input struct{ Config map[string]any }
		if err := readJSON(w, r, &input); err != nil {
			problem(w, 400, err.Error())
			return
		}
		if err := config.ValidateNode(input.Config); err != nil {
			problem(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]any{"ok": true, "config": input.Config})
		return
	}
	if r.URL.Path == "/admin/api/nodes" && (r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE") || r.URL.Path == "/admin/api/nodes/move" && r.Method == "POST" {
		var payload map[string]any
		if err := readJSON(w, r, &payload); err != nil || payload == nil {
			problem(w, 400, "请求 JSON 必须为对象")
			return
		}
		err := s.repository.Mutate(r.Header.Get("X-Profile"), func(doc config.Document) error {
			if r.URL.Path == "/admin/api/nodes/move" {
				return config.MoveNode(doc, payload)
			}
			return config.EditNode(doc, r.Method, payload)
		})
		if err != nil {
			problem(w, 400, err.Error())
			return
		}
		respond(w, 200, map[string]any{"ok": true})
		return
	}
	problem(w, 404, "接口不存在")
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var input struct{ Username, Password string }
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return
	}
	if len(input.Username) > 64 || len(input.Password) > 1024 {
		problem(w, 400, "账号或密码长度无效")
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	keys := []string{"ip:" + host, "account:" + strings.ToLower(input.Username)}
	now := s.now()
	s.mu.Lock()
	for key, v := range s.failures {
		if now.Sub(v.Since) >= 15*time.Minute {
			delete(s.failures, key)
		}
	}
	for _, key := range keys {
		if s.failures[key].Count >= 5 {
			s.mu.Unlock()
			w.Header().Set("Retry-After", "900")
			problem(w, 429, "登录失败次数过多，请稍后再试")
			return
		}
	}
	if len(s.failures) > 4096 {
		s.mu.Unlock()
		problem(w, 429, "登录请求过多，请稍后重试")
		return
	}
	for _, key := range keys {
		v := s.failures[key]
		if v.Since.IsZero() {
			v.Since = now
		}
		v.Count++
		s.failures[key] = v
	}
	s.mu.Unlock()
	select {
	case s.hashSlots <- struct{}{}:
	default:
		problem(w, 429, "登录请求过多，请稍后重试")
		return
	}
	valid := legacycrypto.VerifyPassword(input.Password, s.account.Salt, s.account.Hash, s.account.Iterations)
	<-s.hashSlots
	valid = valid && subtle.ConstantTimeCompare([]byte(input.Username), []byte(s.account.Username)) == 1
	if !valid {
		problem(w, 403, "账号或密码错误")
		return
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		problem(w, 500, "会话创建失败")
		return
	}
	token := base64.RawURLEncoding.EncodeToString(random)
	s.mu.Lock()
	for key, v := range s.sessions {
		if !now.Before(v.Expires) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 8 {
		var oldest [32]byte
		var stamp time.Time
		for key, v := range s.sessions {
			if stamp.IsZero() || v.Created.Before(stamp) {
				oldest = key
				stamp = v.Created
			}
		}
		delete(s.sessions, oldest)
	}
	s.sessions[sha256.Sum256([]byte(token))] = session{Created: now, Expires: now.Add(12 * time.Hour)}
	for _, key := range keys {
		delete(s.failures, key)
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Value: token, Path: "/admin", MaxAge: 12 * 3600, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]any{"ok": true, "token": token})
}
