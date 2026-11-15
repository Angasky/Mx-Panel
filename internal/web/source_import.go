package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"

	"github.com/Angasky/dingzhi-ban/internal/subsource"
)

func (s *Server) sourceImportRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != "POST" || (r.URL.Path != "/admin/api/import-subscription" && r.URL.Path != "/admin/api/import-subscription/preview") {
		return false
	}
	var input struct {
		Selected []int  `json:"selected"`
		Revision string `json:"revision"`
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
	packed, _ := json.Marshal([]string{id, input.URL, text})
	digest := sha256.Sum256(packed)
	revision := hex.EncodeToString(digest[:])
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
		choices := []map[string]any{}
		protocols := map[string]int{}
		for index, node := range batch.Nodes {
			kind, _ := node["type"].(string)
			if kind == "http" && node["tls"] == true {
				kind = "https"
			}
			protocols[kind]++
			choices = append(choices, map[string]any{"index": index, "name": node["name"], "type": kind})
		}
		respond(w, 200, map[string]any{"nodes": choices, "revision": revision, "total": len(batch.Nodes), "protocols": protocols, "skipped": batch.Skipped, "groups": groups})
		return true
	}
	if input.Selected != nil {
		if input.Revision == "" || input.Revision != revision {
			problem(w, 409, "上游订阅内容或来源已变化，请重新预览并选择节点")
			return true
		}
		if len(input.Selected) == 0 || len(input.Selected) > subsource.MaxNodes {
			problem(w, 400, "请选择至少一个节点，最多 20000 个")
			return true
		}
		selected := map[int]bool{}
		for _, index := range input.Selected {
			if index < 0 || index >= len(batch.Nodes) || selected[index] {
				problem(w, 400, "节点选择越界或重复，请重新预览")
				return true
			}
			selected[index] = true
		}
		nodes := make([]map[string]any, 0, len(selected))
		for index, node := range batch.Nodes {
			if selected[index] {
				nodes = append(nodes, node)
			}
		}
		batch.Nodes = nodes
	} else if input.Revision != "" {
		problem(w, 400, "带预览版本的导入必须明确选择节点")
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
