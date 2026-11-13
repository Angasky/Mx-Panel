package web

import "net/http"

func (s *Server) sniRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/sni" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var input struct {
		ServerID   string `json:"serverId"`
		Candidates []string
		Force      bool
		Mode       string
	}
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return true
	}
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	var result map[string]any
	switch input.Mode {
	case "catalog":
		result, err = manager.SNICatalog()
	case "baseline":
		result, err = manager.BuildSNICatalog(r.Context(), input.ServerID, input.Candidates)
	case "tcp", "":
		result, err = manager.ScanSNITCP(r.Context(), input.ServerID, input.Candidates)
	default:
		problem(w, 400, "SNI 测试模式无效")
		return true
	}
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	respond(w, 200, result)
	return true
}
