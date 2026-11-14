package web

import (
	"net/http"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type serverObservation struct {
	Status    string `json:"status"`
	Source    string `json:"source"`
	SampledAt int64  `json:"sampledAt,omitempty"`
}

func observationStatus(at int64, ok bool, now time.Time, ttl int64) string {
	if at <= 0 || at > now.Unix()+1 {
		return "unknown"
	}
	if now.Unix()-at > ttl {
		return "stale"
	}
	if !ok {
		return "failed"
	}
	return "fresh"
}

// Snapshot local observations only: no SSH, Pull request, probe API, or writes.
func (s *Server) serverObservations(rows []remote.Record, now time.Time) map[string]serverObservation {
	s.agentMu.Lock()
	entries, agentErr := s.readAgents()
	views := make(map[string]agentObservation, len(rows))
	for _, row := range rows {
		id := stringField(row, "id")
		v := s.agentViews[id]
		views[id] = agentObservation{At: v.At, Digest: v.Digest}
	}
	s.agentMu.Unlock()
	result := make(map[string]serverObservation, len(rows))
	for _, row := range rows {
		id := stringField(row, "id")
		v := serverObservation{Status: "unknown", Source: "history"}
		switch {
		case probeLinked(row):
			v.Status, v.Source = "external", "komari"
		case agentErr != nil:
			v.Source = "unknown"
		case entries[id].Enabled:
			entry, view := entries[id], views[id]
			v.Source = "agent"
			if entry.Revision != "" && entry.Revision != agentServerRevision(row) {
				break
			}
			v.Status = "pending"
			if entry.Digest != "" && view.Digest == entry.Digest && !view.At.IsZero() {
				v.SampledAt = view.At.Unix()
				v.Status = observationStatus(v.SampledAt, true, now, 90)
			}
		default:
			enabled, point, err := s.history.Latest(id)
			if err != nil {
				break
			}
			if !enabled {
				v.Status = "paused"
				break
			}
			v.Status = "pending"
			if point != nil {
				v.SampledAt = point.Time
				v.Status = observationStatus(point.Time, point.OK, now, 120)
			}
		}
		result[id] = v
	}
	return result
}

func (s *Server) serverObservationsRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/observations" {
		return false
	}
	if r.Method != "GET" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	m, err := s.remoteManager()
	if err != nil {
		problem(w, 500, "服务器数据读取失败")
		return true
	}
	rows, err := m.List()
	if err != nil {
		problem(w, 500, "服务器数据读取失败")
		return true
	}
	now := s.now()
	w.Header().Set("Cache-Control", "no-store")
	respond(w, 200, map[string]any{"generatedAt": now.Unix(), "observations": s.serverObservations(rows, now)})
	return true
}
