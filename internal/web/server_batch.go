package web

import (
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/http"
)

func (s *Server) serverBatchRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/batch-edit" && r.URL.Path != "/admin/api/servers/batch-install" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	if r.URL.Path == "/admin/api/servers/batch-install" {
		var in struct {
			IDs           []string `json:"ids"`
			Confirmed     bool     `json:"confirmed"`
			StopOnFailure bool     `json:"stopOnFailure"`
		}
		if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		if r.Method == "POST" {
			if readJSON(w, r, &in) != nil || len(in.IDs) == 0 {
				problem(w, 400, "请选择服务器")
				return true
			}
		}
		batch, e := m.InstallBatch(in.IDs, in.Confirmed, in.StopOnFailure, r.Method == "DELETE")
		if e != nil {
			problem(w, 409, e.Error())
		} else {
			for i := range batch.Items {
				batch.Items[i].Revision = ""
			}
			respond(w, 200, batch)
		}
		return true
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		Rows      []remote.Record `json:"rows"`
		Confirmed bool            `json:"confirmed"`
	}
	if readJSON(w, r, &in) != nil || !in.Confirmed || len(in.Rows) == 0 || len(in.Rows) > 20 {
		problem(w, 400, "请确认 1–20 台服务器的修改")
		return true
	}
	seen := map[string]bool{}
	for _, row := range in.Rows {
		id := stringField(row, "id")
		if id == "" || seen[id] {
			problem(w, 400, "服务器标识无效或重复")
			return true
		}
		seen[id] = true
		for k := range row {
			if k != "id" && k != "name" && k != "nodeAddress" && k != "installType" {
				problem(w, 400, "批量编辑包含不支持字段")
				return true
			}
		}
		if k, ok := row["installType"]; ok && k != "xray" && k != "sing-box" {
			problem(w, 400, "批量内核类型仅支持 Xray / sing-box")
			return true
		}
	}
	results := []map[string]any{}
	for _, row := range in.Rows {
		id := stringField(row, "id")
		_, e := m.Save(row)
		result := map[string]any{"id": id, "ok": e == nil}
		if e != nil {
			result["error"] = e.Error()
		}
		results = append(results, result)
	}
	respond(w, 200, map[string]any{"results": results})
	return true
}
