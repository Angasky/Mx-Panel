package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

type coreAgentTask struct {
	ID      string             `json:"id"`
	Expires int64              `json:"expires"`
	Plan    remote.CoreRPCPlan `json:"plan"`
}
type coreAgentResult struct {
	ID     string `json:"id"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}
type coreAgentPeer struct {
	digest, revision string
	seen             time.Time
	queue            chan coreAgentTask
	pending          map[string]chan coreAgentResult
	polling          bool
}
type coreAgentHub struct {
	mu    sync.Mutex
	peers map[string]*coreAgentPeer
}

func (s *Server) coreAgentIdentity(id, digest string) (string, bool) {
	s.agentMu.Lock()
	entries, e := s.readAgents()
	entry := entries[id]
	s.agentMu.Unlock()
	if e != nil || !entry.Enabled || entry.Digest != digest || entry.Revision == "" {
		return "", false
	}
	m, e := s.remoteManager()
	if e != nil {
		return "", false
	}
	r, e := m.Record(id)
	if e != nil || r["installType"] != "xray" || entry.Revision != agentServerRevision(r) {
		return "", false
	}
	return entry.Revision, true
}
func (s *Server) resolveCoreAgent(id string, record remote.Record) remote.CoreRPC {
	h := &s.coreAgents
	h.mu.Lock()
	p := h.peers[id]
	ready := p != nil && p.revision == agentServerRevision(record) && time.Since(p.seen) < 45*time.Second
	h.mu.Unlock()
	if !ready {
		return nil
	}
	return func(ctx context.Context, plan remote.CoreRPCPlan) (string, error) {
		if revision, ok := s.coreAgentIdentity(id, p.digest); !ok || revision != p.revision {
			return "", errors.New("Agent 节点 API 授权已变化")
		}
		raw := make([]byte, 16)
		if _, e := rand.Read(raw); e != nil {
			return "", e
		}
		task := coreAgentTask{ID: hex.EncodeToString(raw), Expires: time.Now().Add(90 * time.Second).Unix(), Plan: plan}
		ch := make(chan coreAgentResult, 1)
		h.mu.Lock()
		if h.peers[id] != p {
			h.mu.Unlock()
			return "", errors.New("Agent 节点 API 连接已变化")
		}
		p.pending[task.ID] = ch
		h.mu.Unlock()
		defer func() { h.mu.Lock(); delete(p.pending, task.ID); h.mu.Unlock() }()
		select {
		case p.queue <- task:
		case <-ctx.Done():
			return "", ctx.Err()
		}
		select {
		case result := <-ch:
			if _, ok := s.coreAgentIdentity(id, p.digest); !ok {
				return "", errors.New("Agent 回执授权失效，请核对配置")
			}
			if result.Error != "" {
				return result.Output, errors.New(result.Error)
			}
			return result.Output, nil
		case <-ctx.Done():
			return "", errors.New("Agent 节点 API 响应超时，结果待核对；未回退 SSH 重放")
		}
	}
}
func (s *Server) agentCorePublic(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/sub/agent-core/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if !s.secure(r) {
		problem(w, 426, "节点 API 必须使用 HTTPS")
		return true
	}
	id := strings.TrimPrefix(r.URL.Path, prefix)
	if id == "" || strings.Contains(id, "/") || len(r.Header.Values("Authorization")) != 1 || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		problem(w, 403, "Agent 凭据无效")
		return true
	}
	digest, ok := s.agentAuthorized(id, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	revision, valid := s.coreAgentIdentity(id, digest)
	if !ok || !valid {
		problem(w, 403, "Agent 节点 API 授权无效")
		return true
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	h := &s.coreAgents
	h.mu.Lock()
	if h.peers == nil {
		h.peers = map[string]*coreAgentPeer{}
	}
	p := h.peers[id]
	if p == nil || p.digest != digest || p.revision != revision {
		if len(h.peers) >= 1024 {
			h.mu.Unlock()
			problem(w, 429, "节点 API 连接过多")
			return true
		}
		p = &coreAgentPeer{digest: digest, revision: revision, queue: make(chan coreAgentTask, 1), pending: map[string]chan coreAgentResult{}}
		h.peers[id] = p
	}
	p.seen = time.Now()
	h.mu.Unlock()
	if r.Method == "POST" {
		var result coreAgentResult
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 5<<20))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&result) != nil || decoder.Decode(new(any)) != io.EOF || len(result.Output) > 3<<20 || len(result.Error) > 4096 {
			problem(w, 400, "节点 API 回执无效")
			return true
		}
		h.mu.Lock()
		ch := p.pending[result.ID]
		h.mu.Unlock()
		if ch == nil {
			problem(w, 409, "此任务已结束，请核对配置")
			return true
		}
		select {
		case ch <- result:
		default:
		}
		respond(w, 200, map[string]bool{"ok": true})
		return true
	}
	h.mu.Lock()
	if p.polling {
		h.mu.Unlock()
		problem(w, 409, "已有节点 API 长轮询")
		return true
	}
	p.polling = true
	h.mu.Unlock()
	defer func() { h.mu.Lock(); p.polling = false; h.mu.Unlock() }()
	timer := time.NewTimer(20 * time.Second)
	defer timer.Stop()
	for {
		select {
		case task := <-p.queue:
			h.mu.Lock()
			active := p.pending[task.ID] != nil
			h.mu.Unlock()
			if !active || task.Expires < time.Now().Unix() {
				continue
			}
			if _, ok := s.coreAgentIdentity(id, digest); !ok {
				problem(w, 403, "Agent 授权已撤销")
				return true
			}
			respond(w, 200, task)
			return true
		case <-timer.C:
			w.WriteHeader(204)
			return true
		case <-r.Context().Done():
			return true
		}
	}
}
