package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
	"net/http"
	"os"
	"path/filepath"
)

type probeHistory struct {
	Points []netprobe.Result `json:"points"`
}

func (s *Server) probePath(id string) string {
	sum := sha256.Sum256([]byte(id))
	return filepath.Join(s.options.Root, "monitor-history", "probe-"+hex.EncodeToString(sum[:])+".json")
}
func (s *Server) readProbes(id string) (probeHistory, error) {
	state := probeHistory{Points: []netprobe.Result{}}
	b, e := os.ReadFile(s.probePath(id))
	if os.IsNotExist(e) {
		return state, nil
	}
	if e != nil {
		return state, e
	}
	if len(b) > 4<<20 {
		return state, errors.New("探测历史超出大小限制")
	}
	if e = json.Unmarshal(b, &state); e != nil {
		return state, e
	}
	filtered := []netprobe.Result{}
	for _, p := range state.Points {
		if p.Time >= s.now().Unix()-86400 && p.Time <= s.now().Unix()+5 {
			filtered = append(filtered, p)
		}
	}
	state.Points = filtered
	return state, nil
}
func (s *Server) recordProbes(id string) {
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	s.agentMu.Lock()
	view := s.agentViews[id]
	points := append([]netprobe.Result{}, view.Probes...)
	s.agentMu.Unlock()
	state, e := s.readProbes(id)
	if e != nil {
		return
	}
	latest := map[string]int64{}
	for _, p := range state.Points {
		if p.Time > latest[p.Name] {
			latest[p.Name] = p.Time
		}
	}
	changed := false
	for _, p := range points {
		if p.Time > latest[p.Name] {
			state.Points = append(state.Points, p)
			changed = true
		}
	}
	if !changed {
		return
	}
	if len(state.Points) > 18000 {
		state.Points = state.Points[len(state.Points)-18000:]
	}
	b, e := json.Marshal(state)
	if e != nil {
		return
	}
	dir := filepath.Dir(s.probePath(id))
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	f, e := os.CreateTemp(dir, ".probe-*")
	if e != nil {
		return
	}
	defer f.Close()
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		return
	}
	if e = f.Sync(); e != nil {
		return
	}
	if e = f.Close(); e != nil {
		return
	}
	os.Rename(f.Name(), s.probePath(id))
}
func (s *Server) probeHistoryAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/probe-history" {
		return false
	}
	if r.Method != "GET" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器读取失败")
		return true
	}
	if _, e = m.Record(id); e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	s.probeMu.Lock()
	defer s.probeMu.Unlock()
	if r.Method == "DELETE" {
		e = os.Remove(s.probePath(id))
		if e != nil && !os.IsNotExist(e) {
			problem(w, 500, "清除探测历史失败")
			return true
		}
	}
	history, e := s.readProbes(id)
	if e != nil {
		problem(w, 500, "读取探测历史失败")
		return true
	}
	s.agentMu.Lock()
	current := append([]netprobe.Result{}, s.agentViews[id].Probes...)
	s.agentMu.Unlock()
	respond(w, 200, map[string]any{"points": history.Points, "current": current, "method": "tcp", "source": "agent", "retentionHours": 24})
	return true
}
