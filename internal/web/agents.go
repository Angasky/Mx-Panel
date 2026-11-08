package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/agentcontrol"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"golang.org/x/net/websocket"
)

type agentRegistration struct {
	Revision string `json:"revision,omitempty"`
	Mode     string `json:"mode,omitempty"`
	URL      string `json:"url,omitempty"`
	Secret   string `json:"secret,omitempty"`
	Enabled  bool   `json:"enabled"`
	Digest   string `json:"digest"`
}
type agentObservation struct {
	Capabilities []string
	View         remote.Record
	At           time.Time
	Digest       string
	Mode         string
}

func (s *Server) readAgents() (map[string]agentRegistration, error) {
	entries := map[string]agentRegistration{}
	b, e := os.ReadFile(filepath.Join(s.options.Root, "agents.json"))
	if os.IsNotExist(e) {
		return entries, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 1<<20 {
		return nil, errors.New("Agent 配置超出限制")
	}
	if e = json.Unmarshal(b, &entries); e != nil || entries == nil {
		return nil, errors.New("Agent 配置损坏")
	}
	return entries, nil
}
func (s *Server) writeAgents(entries map[string]agentRegistration) error {
	b, e := json.Marshal(entries)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".agents-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "agents.json"))
}
func (s *Server) agentAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据读取失败")
		return true
	}
	if _, e = m.Record(id); e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil {
		problem(w, 500, "Agent 配置读取失败")
		return true
	}
	token := ""
	if r.Method == "POST" {
		var input struct {
			Mode string `json:"mode"`
			URL  string `json:"url"`
		}
		if readJSON(w, r, &input) != nil {
			problem(w, 400, "Agent 配置无效")
			return true
		}
		if input.Mode == "" {
			input.Mode = "auto"
		}
		if input.Mode != "auto" && input.Mode != "http" && input.Mode != "websocket" && input.Mode != "pull" {
			problem(w, 400, "Agent 模式无效")
			return true
		}
		if input.Mode == "pull" {
			record, _ := m.Record(id)
			u, e := url.Parse(input.URL)
			if e != nil || u.Scheme != "https" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "/metrics" || !strings.EqualFold(u.Hostname(), strings.Trim(stringField(record, "host"), "[]")) {
				problem(w, 400, "Pull 地址必须为已登记主机的 HTTPS /metrics 地址")
				return true
			}
		}
		if len(entries) >= 1000 {
			if _, ok := entries[id]; !ok {
				problem(w, 400, "Agent 数量超出限制")
				return true
			}
		}
		b := make([]byte, 32)
		if _, e = rand.Read(b); e != nil {
			problem(w, 500, "令牌生成失败")
			return true
		}
		token = base64.RawURLEncoding.EncodeToString(b)
		sum := sha256.Sum256([]byte(token))
		record, _ := m.Record(id)
		entry := agentRegistration{Enabled: true, Digest: hex.EncodeToString(sum[:]), Mode: input.Mode, Revision: agentServerRevision(record)}
		if input.Mode == "pull" {
			entry.URL = input.URL
			entry.Secret, e = m.SealUser(remote.Record{"token": token})
			if e != nil {
				problem(w, 500, "Agent 凭据加密失败")
				return true
			}
		}
		entries[id] = entry
	}
	if r.Method == "DELETE" {
		delete(entries, id)
	}
	if r.Method != "GET" {
		if e = s.writeAgents(entries); e != nil {
			problem(w, 500, "Agent 配置保存失败")
			return true
		}
		delete(s.agentViews, id)
		os.Remove(s.taskPath(id))
	}
	observation := s.agentViews[id]
	result := map[string]any{"configuredMode": entries[id].Mode, "pullURL": entries[id].URL, "enabled": entries[id].Enabled, "connected": !observation.At.IsZero() && s.now().Sub(observation.At) < 90*time.Second, "mode": observation.Mode, "lastSeen": int64(0)}
	if !observation.At.IsZero() {
		result["lastSeen"] = observation.At.Unix()
	}
	if token != "" {
		result["token"] = token
		result["path"] = "/sub/agent/" + id
	}
	respond(w, 200, result)
	return true
}
func (s *Server) agentAuthorized(id, token string) (string, bool) {
	if len(token) != 43 {
		return "", false
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil {
		return "", false
	}
	entry := entries[id]
	sum := sha256.Sum256([]byte(token))
	digest, e := hex.DecodeString(entry.Digest)
	return entry.Digest, e == nil && entry.Enabled && subtle.ConstantTimeCompare(sum[:], digest) == 1
}
func (s *Server) acceptAgent(ctx context.Context, id, digest, raw, mode string) error {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil || !entries[id].Enabled || entries[id].Digest != digest {
		return errors.New("Agent 凭据已撤销")
	}
	if configured := entries[id].Mode; configured != "auto" && configured != mode {
		return errors.New("Agent 上报模式与登记模式不一致")
	}
	// Limit parse/delta work per registered server and serialize with token revocation.
	if v := s.agentViews[id]; !v.At.IsZero() && s.now().Sub(v.At) < 4*time.Second {
		return nil
	}
	m, e := s.remoteManager()
	if e != nil {
		return e
	}
	record, e := m.Record(id)
	if e != nil {
		return e
	}
	if entries[id].Revision != "" && entries[id].Revision != agentServerRevision(record) {
		return errors.New("服务器连接信息已变化，请重新生成 Agent 配置")
	}
	view, e := m.AgentMetrics(ctx, id, digest, raw)
	if e != nil {
		return e
	}
	s.agentViews[id] = agentObservation{View: view, At: s.now(), Digest: digest, Mode: mode}
	return nil
}
func (s *Server) agentPublic(w http.ResponseWriter, r *http.Request) bool {
	if !strings.HasPrefix(r.URL.Path, "/sub/agent/") {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.secure(r) {
		problem(w, 426, "Agent 必须使用 HTTPS")
		return true
	}
	id := strings.TrimPrefix(r.URL.Path, "/sub/agent/")
	authorization := r.Header.Get("Authorization")
	if !strings.HasPrefix(authorization, "Bearer ") || id == "" || strings.Contains(id, "/") {
		problem(w, 403, "Agent 凭据无效")
		return true
	}
	token := strings.TrimPrefix(authorization, "Bearer ")
	digest, ok := s.agentAuthorized(id, token)
	if !ok {
		problem(w, 403, "Agent 凭据无效")
		return true
	}
	if r.Method == "POST" {
		select {
		case s.agentSlots <- struct{}{}:
			defer func() { <-s.agentSlots }()
		default:
			problem(w, 429, "Agent 请求过多")
			return true
		}
		var input agentcontrol.Report
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&input) != nil || decoder.Decode(new(any)) != io.EOF || len(input.Sample) > 512<<10 {
			problem(w, 400, "采样请求无效")
			return true
		}
		if e := s.acceptAgent(r.Context(), id, digest, input.Sample, "http"); e != nil {
			problem(w, 400, "采样被拒绝")
			return true
		}
		respond(w, 200, s.agentAcknowledgement(id, digest, input))
		return true
	}
	if r.Method == "GET" && strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		select {
		case s.agentSlots <- struct{}{}:
			defer func() { <-s.agentSlots }()
		default:
			problem(w, 429, "Agent 连接过多")
			return true
		}
		websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
			defer ws.Close()
			ws.MaxPayloadBytes = 2 << 20
			for {
				ws.SetDeadline(time.Now().Add(120 * time.Second))
				var input agentcontrol.Report
				if websocket.JSON.Receive(ws, &input) != nil {
					return
				}
				if len(input.Sample) > 512<<10 || s.acceptAgent(r.Context(), id, digest, input.Sample, "websocket") != nil {
					return
				}
				if websocket.JSON.Send(ws, s.agentAcknowledgement(id, digest, input)) != nil {
					return
				}
			}
		}}.ServeHTTP(w, r)
		return true
	}
	problem(w, 405, "Agent 仅支持 HTTP POST 或 WebSocket")
	return true
}
func (s *Server) serverMetrics(ctx context.Context, id string) (remote.Record, error) {
	s.agentMu.Lock()
	entries, e := s.readAgents()
	entry := entries[id]
	v := s.agentViews[id]
	s.agentMu.Unlock()
	if e != nil {
		return nil, errors.New("Agent 配置读取失败")
	}
	if entry.Enabled {
		if entry.Mode == "pull" && (v.Digest != entry.Digest || v.At.IsZero() || s.now().Sub(v.At) >= 15*time.Second) {
			m, e := s.remoteManager()
			if e != nil {
				return nil, e
			}
			record, e := m.Record(id)
			if e != nil {
				return nil, e
			}
			u, e := url.Parse(entry.URL)
			if e != nil || !strings.EqualFold(u.Hostname(), strings.Trim(stringField(record, "host"), "[]")) {
				return nil, errors.New("Pull 主机已变化，请重新登记")
			}
			secret, e := m.OpenUser(entry.Secret)
			if e != nil {
				return nil, errors.New("Pull 凭据无法解密")
			}
			client, transport := agentPullClient()
			defer transport.CloseIdleConnections()
			req, e := http.NewRequestWithContext(ctx, "GET", entry.URL, nil)
			if e != nil {
				return nil, e
			}
			req.Header.Set("Authorization", "Bearer "+stringField(secret, "token"))
			res, e := client.Do(req)
			if e != nil {
				return nil, errors.New("Pull 连接失败")
			}
			defer res.Body.Close()
			if res.StatusCode != 200 {
				return nil, errors.New("Pull 采样失败")
			}
			var payload agentcontrol.Report
			if json.NewDecoder(io.LimitReader(res.Body, 600<<10)).Decode(&payload) != nil {
				return nil, errors.New("Pull 数据无效")
			}
			if e = s.acceptAgent(ctx, id, entry.Digest, payload.Sample, "pull"); e != nil {
				return nil, e
			}
			s.agentAcknowledgement(id, entry.Digest, payload)
			s.agentMu.Lock()
			v = s.agentViews[id]
			s.agentMu.Unlock()
		}
		if v.Digest != entry.Digest || v.At.IsZero() || s.now().Sub(v.At) > 90*time.Second {
			return nil, errors.New("Agent 尚未连接或采样已过期")
		}
		return v.View, nil
	}
	m, e := s.remoteManager()
	if e != nil {
		return nil, e
	}
	return m.Metrics(ctx, id)
}

func agentPullClient() (*http.Client, *http.Transport) {
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupIPAddr(ctx, host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if ip.IP.IsUnspecified() || ip.IP.IsLoopback() || ip.IP.IsLinkLocalUnicast() || ip.IP.IsMulticast() {
				continue
			}
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.IP.String(), port))
		}
		return nil, errors.New("Pull 地址不可用")
	}, TLSHandshakeTimeout: 10 * time.Second}
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("Pull 不允许重定向") }}
	return client, transport
}

func agentServerRevision(record remote.Record) string {
	raw, _ := json.Marshal([]any{record["host"], record["sshPort"], record["sshUser"], record["fingerprint"], record["installType"]})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
