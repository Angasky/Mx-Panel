package web

import "net/http"

func (s *Server) installRoutes(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if !(path == "/admin/api/servers/install" && r.Method == "POST" || path == "/admin/api/servers/jobs" && r.Method == "GET") {
		return false
	}
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	if r.Method == "GET" {
		job, err := manager.InstallJob(r.URL.Query().Get("id"))
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, job)
		}
		return true
	}
	var input struct {
		ID        string `json:"id"`
		Confirmed bool   `json:"confirmed"`
	}
	if readJSON(w, r, &input) != nil || input.ID == "" {
		problem(w, 400, "请选择服务器并确认安装")
		return true
	}
	job, err := manager.StartInstall(input.ID, input.Confirmed)
	if err != nil {
		problem(w, 400, err.Error())
	} else {
		respond(w, 202, map[string]any{"ok": true, "job": job})
	}
	return true
}
