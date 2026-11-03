package web

import (
	"net/http"

	"github.com/Angasky/dingzhi-ban/internal/subsource"
)

func (s *Server) sourceImportRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" || (r.URL.Path != "/admin/api/import-subscription" && r.URL.Path != "/admin/api/import-subscription/preview") {
		return false
	}
	var input struct {
		URL      string
		Conflict string
		Groups   any
	}
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return true
	}
	id := r.Header.Get("X-Profile")
	groups, err := s.repository.GroupOptions(id)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if input.Conflict == "" {
		input.Conflict = "rename"
	}
	if input.Conflict != "rename" && input.Conflict != "replace" && input.Conflict != "skip" {
		problem(w, 400, "重名处理方式无效")
		return true
	}
	select {
	case s.sourceSlots <- struct{}{}:
		defer func() { <-s.sourceSlots }()
	default:
		problem(w, 429, "订阅读取任务较多，请稍后重试")
		return true
	}
	text, err := s.fetchSubscription(r.Context(), input.URL)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	batch, err := subsource.Parse(text)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if r.Context().Err() != nil {
		problem(w, 408, "订阅读取已取消")
		return true
	}
	if r.URL.Path == "/admin/api/import-subscription/preview" {
		groups, err = s.repository.GroupOptions(id)
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		protocols := map[string]int{}
		for _, node := range batch.Nodes {
			kind, _ := node["type"].(string)
			if kind == "http" && node["tls"] == true {
				kind = "https"
			}
			protocols[kind]++
		}
		respond(w, 200, map[string]any{"total": len(batch.Nodes), "protocols": protocols, "skipped": batch.Skipped, "groups": groups})
		return true
	}
	result, err := s.repository.ImportSubscription(id, batch.Nodes, input.Conflict, input.Groups, batch.SkippedCount)
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	result["ok"] = true
	respond(w, 200, result)
	return true
}
