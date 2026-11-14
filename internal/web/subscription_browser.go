package web

import (
	"mime"
	"net/http"
	"strconv"
	"strings"
)

// This is convenience filtering, not authenticated client identification.
// Native clients using browser-like headers can disable the per-profile option.
func browserSubscriptionRequest(r *http.Request) bool {
	for _, value := range r.Header.Values("Sec-Fetch-Mode") {
		if strings.EqualFold(strings.TrimSpace(value), "navigate") {
			return true
		}
	}
	for _, value := range r.Header.Values("Sec-Fetch-Dest") {
		switch strings.ToLower(strings.TrimSpace(value)) {
		case "document", "iframe", "frame":
			return true
		}
	}
	for _, value := range r.Header.Values("User-Agent") {
		if strings.Contains(strings.ToLower(value), "mozilla/") {
			return true
		}
	}
	for _, value := range r.Header.Values("Accept") {
		for _, part := range strings.Split(strings.ToLower(value), ",") {
			media, params, err := mime.ParseMediaType(strings.TrimSpace(part))
			if err != nil {
				continue
			}
			if weight, exists := params["q"]; exists {
				q, err := strconv.ParseFloat(weight, 64)
				if err != nil || q <= 0 || q > 1 {
					continue
				}
			}
			if media == "text/html" || media == "application/xhtml+xml" {
				return true
			}
		}
	}
	return false
}
func (s *Server) subscriptionBrowserRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/subscription-browser-access" {
		return false
	}
	id := r.Header.Get("X-Profile")
	var enabled bool
	var err error
	switch r.Method {
	case "GET":
		enabled, err = s.repository.SubscriptionBrowserAccess(id)
	case "PUT":
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if readJSON(w, r, &input) != nil || input.Enabled == nil {
			problem(w, 400, "请提交浏览器访问拦截开关")
			return true
		}
		enabled = *input.Enabled
		err = s.repository.SetSubscriptionBrowserAccess(id, enabled)
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	if err != nil {
		problem(w, 400, err.Error())
		return true
	}
	respond(w, 200, map[string]any{"enabled": enabled})
	return true
}
