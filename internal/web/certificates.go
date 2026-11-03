package web

import "net/http"

func (s *Server) certificateRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/certificates" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	var job map[string]any
	if r.Method == "GET" {
		job, err = manager.CertificateJob(r.URL.Query().Get("id"), r.URL.Query().Get("job"))
	} else {
		var payload map[string]any
		if e := readJSON(w, r, &payload); e != nil || payload == nil {
			problem(w, 400, "请求 JSON 必须为对象")
			return true
		}
		job, err = manager.StartCertificate(stringField(payload, "serverId"), stringField(payload, "serverName"))
	}
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	status := 200
	if r.Method == "POST" {
		status = 202
	}
	respond(w, status, map[string]any{"job": job})
	return true
}
