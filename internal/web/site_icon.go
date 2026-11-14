package web

import (
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
)

// Fixed, local fallback artwork. User SVG uploads remain forbidden.
const defaultSiteIcon = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#334155"/><path d="M14 48V16h8l10 17 10-17h8v32h-8V31L32 46 22 31v17z" fill="#fff"/></svg>`

// Public branding only; no authentication redirect or external image fetching.
// Avoid browser reuse across Logo changes, including requests made before JS.
func (s *Server) siteIconPublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, 405, "请求方法不支持")
		return
	}
	s.siteInfoMu.Lock()
	c, err := s.readSiteInfo()
	s.siteInfoMu.Unlock()
	// Branding failure must not leave a previously uploaded icon cached. The
	// settings API still reports the damaged configuration for administrators.
	body, kind := []byte(defaultSiteIcon), "image/svg+xml"
	if err == nil && c.Logo != "" {
		prefix, encoded, ok := strings.Cut(c.Logo, ",")
		if ok {
			if decoded, e := base64.StdEncoding.Strict().DecodeString(encoded); e == nil {
				body = decoded
				kind = "image/png"
				if prefix == "data:image/jpeg;base64" {
					kind = "image/jpeg"
				}
			}
		}
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
