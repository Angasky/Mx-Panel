// Package web contains the native Go management HTTP service.
package web

import (
	"context"
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
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/geo"
	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/monitorhistory"
	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"github.com/Angasky/dingzhi-ban/internal/subsource"
)

type Options struct {
	Root, AuthFile, AdminHTML, Version   string
	TrustLoopbackProxy, LocalDevelopment bool
	ReleaseUpdater                       *releaseupdate.Manager
	ServiceUninstaller                   ServiceUninstaller
}
type account struct {
	Username   string `json:"username"`
	Salt       string `json:"salt"`
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
}
type session struct{ Expires, Created time.Time }
type failure struct {
	Count int
	Since time.Time
}
type Server struct {
	aiMu                 sync.Mutex
	aiActive             map[string]bool
	aiHTTP               *http.Client
	probeCacheMu         sync.Mutex
	probeCache           map[string]*probeCacheEntry
	probeSyncMu          sync.Mutex
	probeHTTP            *http.Client
	rolloutMu            sync.Mutex
	rolloutOwner         string
	externalMu           sync.Mutex
	fetchExternalTraffic func(context.Context, string) (subsource.Traffic, error)
	notificationMu       sync.Mutex
	metadataMu           sync.Mutex
	probeMu              sync.Mutex
	agentMu              sync.Mutex
	agentViews           map[string]agentObservation
	agentSlots           chan struct{}
	shareMu              sync.Mutex
	shareSlots           chan struct{}
	shareStreamSlots     chan struct{}
	history              *monitorhistory.Store
	historyOnce          sync.Once
	historyDone          chan struct{}
	options              Options
	updates              goUpdates
	account              account
	mu                   sync.Mutex
	userAdminMu          sync.Mutex
	userMu               sync.Mutex
	sessions             map[[32]byte]session
	failures             map[string]failure
	hashSlots            chan struct{}
	sourceSlots          chan struct{}
	fetchSubscription    func(context.Context, string) (string, error)
	countryLookup        func(context.Context, string) (geo.Country, error)
	now                  func() time.Time
	repository           *config.Repository
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
	var doc map[string]any
	if err = json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	sessions, err := readSessions(doc, auth, time.Now())
	if err != nil {
		return nil, err
	}
	failures, err := readLoginFailures(doc, auth, time.Now())
	if err != nil {
		return nil, err
	}
	repository := &config.Repository{Root: options.Root}
	ignored, _ := doc["goIgnoredRelease"].(string)
	return &Server{agentViews: map[string]agentObservation{}, agentSlots: make(chan struct{}, 128), shareSlots: make(chan struct{}, 4), shareStreamSlots: make(chan struct{}, 32), history: monitorhistory.New(options.Root), options: options, updates: goUpdates{ignored: ignored}, account: auth, sessions: sessions, failures: failures, hashSlots: make(chan struct{}, 2), sourceSlots: make(chan struct{}, 4), fetchSubscription: subsource.NewClient().Fetch, countryLookup: geo.New().Lookup, now: time.Now, repository: repository}, nil
}

func respond(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Mxioc-Create-Idempotency", "1")
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
func requestSessionToken(r *http.Request) string {
	token := ""
	if strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	}
	if token == "" {
		if cookie, err := r.Cookie("mxioc_session"); err == nil {
			token = cookie.Value
		}
	}
	return token
}
func (s *Server) authorized(r *http.Request) bool {
	token := requestSessionToken(r)
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
	if r.Method == http.MethodHead {
		if r.Header.Get("Upgrade") != "" {
			problem(w, 405, "升级连接必须使用 GET")
			return
		}
		w = headResponse{w}
		copy := r.Clone(r.Context())
		copy.Method = http.MethodGet
		r = copy
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("X-Frame-Options", "DENY")
	if r.URL.Path == "/healthz" && (r.Method == "GET" || r.Method == "HEAD") {
		respond(w, 200, map[string]any{"ok": true, "runtime": "go", "version": s.options.Version})
		return
	}
	if r.URL.Path == "/" || r.URL.Path == "/admin" || r.URL.Path == "/admin/" {
		if r.Method != "GET" && r.Method != "HEAD" {
			problem(w, 405, "请求方法不支持")
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		path := s.options.AdminHTML
		if path == "" {
			path = filepath.Join(s.options.Root, "index.html")
		}
		http.ServeFile(w, r, path)
		return
	}
	if craftAsset(w, r) {
		return
	}
	if uiFontAsset(w, r) {
		return
	}
	if globeAsset(w, r) {
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/admin/api/") {
		if s.agentPublic(w, r) {
			return
		}
		if s.monitorSharePublic(w, r) {
			return
		}
		if s.publicRoutes(w, r) {
			return
		}
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
	if member, ok := s.member(r); ok {
		s.memberRoutes(w, r, member)
		return
	}
	if !s.authorized(r) {
		problem(w, 401, "请重新登录")
		return
	}
	if s.aiRoute(w, r, nil) {
		return
	}
	if s.clientOptionsRoute(w, r) {
		return
	}
	if s.probeBatchRoute(w, r) {
		return
	}
	if s.probeSyncRoute(w, r) {
		return
	}
	if s.externalTrafficRoute(w, r) {
		return
	}
	if s.notificationRoute(w, r) {
		return
	}
	if s.onlineRoute(w, r) {
		return
	}
	if s.probeHistoryAdmin(w, r) {
		return
	}
	if s.billingRoute(w, r) {
		return
	}
	if s.renewalRoute(w, r) {
		return
	}
	if s.metadataRoute(w, r) {
		return
	}
	if s.agentRolloutRoute(w, r) {
		return
	}
	if s.agentDeploy(w, r) {
		return
	}
	if s.agentControlAdmin(w, r) {
		return
	}
	if s.agentAdmin(w, r) {
		return
	}
	if s.monitorShareAdmin(w, r) {
		return
	}
	if s.monitorHistoryRoute(w, r) {
		return
	}
	if s.userAdminRoute(w, r) {
		return
	}
	if r.URL.Path == "/admin/api/conversions" && s.publicRoutes(w, r) {
		return
	}
	if s.flagRoutes(w, r) || s.sourceImportRoutes(w, r) || s.linkRoutes(w, r) || s.editRoutes(w, r) {
		return
	}
	if r.URL.Path == "/admin/api/logout" && r.Method == "POST" {
		token := requestSessionToken(r)
		s.mu.Lock()
		err := s.updateSessions(func(entries map[[32]byte]session) { delete(entries, sha256.Sum256([]byte(token))) })
		s.mu.Unlock()
		if err != nil {
			problem(w, 500, "退出登录保存失败，请重试")
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Path: "/admin", MaxAge: -1, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
		respond(w, 200, map[string]any{"ok": true})
		return
	}
	if s.uninstallRoute(w, r) {
		return
	}
	if s.goUpdateRoutes(w, r) {
		return
	}
	if r.URL.Path == "/admin/api/account" && r.Method == "GET" {
		s.mu.Lock()
		username := s.account.Username
		s.mu.Unlock()
		respond(w, 200, map[string]any{"username": username, "role": "admin"})
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
			value, err := s.repository.SnapshotJSON(id)
			if err != nil {
				problem(w, 400, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			_, _ = w.Write(value)
			return
		case "/admin/api/raw":
			value, err := s.repository.RawJSON(id)
			if err != nil {
				problem(w, 400, err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(200)
			_, _ = w.Write(value)
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
		var uri any
		if shared, err := links.Export(input.Config); err == nil {
			uri = shared
		}
		respond(w, 200, map[string]any{"ok": true, "config": input.Config, "uri": uri})
		return
	}
	if r.URL.Path == "/admin/api/nodes" && (r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE") || r.URL.Path == "/admin/api/nodes/move" && r.Method == "POST" {
		var payload map[string]any
		if err := readJSON(w, r, &payload); err != nil || payload == nil {
			problem(w, 400, "请求 JSON 必须为对象")
			return
		}
		if r.Method == "POST" && r.URL.Path == "/admin/api/nodes" {
			if _, exists := payload["addToGroups"]; !exists {
				payload["addToGroups"] = true
			}
		}
		var err error
		if r.URL.Path == "/admin/api/nodes/move" {
			err = s.repository.MoveNode(r.Header.Get("X-Profile"), payload)
		} else {
			err = s.repository.EditNode(r.Header.Get("X-Profile"), r.Method, payload)
		}
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
	if utf8.RuneCountInString(input.Username) > 64 || len(input.Password) > 1024 {
		problem(w, 400, "账号或密码长度无效")
		return
	}
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	keys := []string{failureKey("ip:" + host), failureKey("account:" + strings.ToLower(input.Username))}
	now := s.now()
	s.mu.Lock()
	nextFailures := copyLoginFailures(s.failures, now)
	for _, key := range keys {
		if nextFailures[key].Count >= 5 {
			s.mu.Unlock()
			w.Header().Set("Retry-After", "900")
			problem(w, 429, "登录失败次数过多，请稍后再试")
			return
		}
	}
	newKeys := 0
	for _, key := range keys {
		if _, ok := nextFailures[key]; !ok {
			newKeys++
		}
	}
	if len(nextFailures)+newKeys > loginFailureLimit {
		s.mu.Unlock()
		problem(w, 429, "登录请求过多，请稍后重试")
		return
	}
	for _, key := range keys {
		v := nextFailures[key]
		if v.Since.IsZero() {
			v.Since = now
		}
		v.Count++
		nextFailures[key] = v
	}
	if err := s.persistLoginFailures(nextFailures); err != nil {
		s.mu.Unlock()
		problem(w, 500, "登录限流保存失败，请重试")
		return
	}
	s.mu.Unlock()
	select {
	case s.hashSlots <- struct{}{}:
	default:
		problem(w, 429, "登录请求过多，请稍后重试")
		return
	}
	s.mu.Lock()
	auth := s.account
	s.mu.Unlock()
	if input.Username != auth.Username {
		s.memberLogin(w, r, input.Username, input.Password, keys)
		return
	}
	valid := legacycrypto.VerifyPassword(input.Password, auth.Salt, auth.Hash, auth.Iterations)
	valid = valid && subtle.ConstantTimeCompare([]byte(input.Username), []byte(auth.Username)) == 1
	nextAuth := auth
	var upgradeErr error
	if valid && auth.Iterations < 600000 {
		nextAuth.Salt, nextAuth.Hash, upgradeErr = legacycrypto.NewPassword(input.Password)
		nextAuth.Iterations = 600000
	}
	<-s.hashSlots
	if upgradeErr != nil {
		problem(w, 500, "密码安全升级失败，请重试")
		return
	}
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
	if s.account != auth {
		s.mu.Unlock()
		problem(w, 403, "账号已变更，请重新登录")
		return
	}
	if err := s.completeLogin(auth, nextAuth, keys, sha256.Sum256([]byte(token))); err != nil {
		s.mu.Unlock()
		problem(w, 500, "登录会话保存失败，请重试")
		return
	}
	s.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "mxioc_session", Value: token, Path: "/admin", MaxAge: 12 * 3600, HttpOnly: true, Secure: r.TLS != nil || !s.options.LocalDevelopment, SameSite: http.SameSiteStrictMode})
	respond(w, 200, map[string]any{"ok": true, "token": token})
}
