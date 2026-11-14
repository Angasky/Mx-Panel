package web

import (
	"net/http"
	"regexp"
	"strings"
)

type monitorEntry struct {
	Home bool   `json:"home"`
	Path string `json:"path"`
}

var monitorEntryPattern = regexp.MustCompile(`^/status/[a-zA-Z0-9][a-zA-Z0-9_-]{0,47}$`)

func validMonitorEntry(e monitorEntry) bool {
	return e.Path == "" || monitorEntryPattern.MatchString(e.Path)
}

// Custom entries are aliases of the public endpoint, never of a tokenized page.
// The original authorization is checked again by monitorSharePublic.
func (s *Server) monitorEntryRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/" && !strings.HasPrefix(r.URL.Path, "/status/") {
		return false
	}
	s.shareMu.Lock()
	c, err := s.readShare()
	s.shareMu.Unlock()
	if err != nil {
		problem(w, 503, "探针入口配置暂不可用，请通过 /admin/ 管理")
		return true
	}
	matched := r.URL.Path == "/" && c.Entry.Home || c.Entry.Path != "" && r.URL.Path == c.Entry.Path
	if !matched {
		return false
	}
	copy := r.Clone(r.Context())
	u := *r.URL
	copy.URL = &u
	copy.URL.Path = "/sub/status-public"
	copy.URL.RawPath = ""
	return s.monitorSharePublic(w, copy)
}
