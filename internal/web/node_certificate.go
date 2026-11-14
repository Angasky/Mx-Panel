package web

import "net/http"

func (s *Server) nodeCertificateRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/nodes/certificate-verification" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		Action    string   `json:"action"`
		Names     []string `json:"names"`
		Revision  string   `json:"revision"`
		Confirmed bool     `json:"confirmed"`
	}
	if readJSON(w, r, &in) != nil || (in.Action != "preview" && in.Action != "apply") {
		problem(w, 400, "证书验证批量请求无效")
		return true
	}
	if in.Action == "apply" && (!in.Confirmed || in.Revision == "") {
		problem(w, 400, "请先预览并确认启用证书验证")
		return true
	}
	v, err := s.repository.ReviewNodeCertificates(r.Header.Get("X-Profile"), in.Names, in.Revision, in.Action == "apply")
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	respond(w, 200, v)
	return true
}
