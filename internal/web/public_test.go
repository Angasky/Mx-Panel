package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestPublicSubscriptionHTTPIsolationHeadersAndRevocation(t *testing.T) {
	s := fixture(t)
	slug := strings.Repeat("a", 50)
	if err := s.repository.Mutate("clash", func(doc map[string]any) error {
		doc["proxies"] = []any{map[string]any{"name": "HY2", "type": "hysteria2", "server": "192.0.2.1", "port": 24443, "password": "fixture-only-password"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.UpdateState("clash", func(p map[string]any) error {
		p["traffic"] = map[string]any{"enabled": true, "enforce": true, "upload": int64(12), "download": int64(34), "total": int64(100)}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	get := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://panel.test"+path, nil)
		r.Header.Set("X-Profile", "other")
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	w := get("GET", "/sub/"+slug)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture-only-password") || w.Header().Get("Subscription-Userinfo") != "upload=12; download=34; total=100" || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Body.String(), w.Header())
	}
	if _, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(w.Header().Get("Profile-Title"), "base64:")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/sub/" + slug, "/convert/" + slug + "/shadowrocket"} {
		getResponse := get("GET", path)
		head := get("HEAD", path)
		if getResponse.Code != 200 || head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != strconv.Itoa(getResponse.Body.Len()) {
			t.Fatal("HEAD differs from GET", path, head.Code)
		}
	}
	for _, path := range []string{"/sub/clash", "/sub/" + strings.Repeat("x", 50), "/sub/" + slug + "/extra", "/convert/" + slug + "/v2rayn-ha"} {
		w := get("GET", path)
		if w.Code != 404 || strings.Contains(w.Body.String(), "fixture-only-password") {
			t.Fatal("unknown capability leaked subscription", w.Code, w.Body.String())
		}
	}
	if w := get("POST", "/sub/"+slug); w.Code != 405 {
		t.Fatal("public mutation allowed")
	}
	if w := request(s, "GET", "/admin/api/conversions", "", "", "", true); w.Code != 401 {
		t.Fatal("management report is public")
	}
	token := login(t, s)
	w = request(s, "GET", "/admin/api/conversions", "", token, "", true)
	var report map[string]any
	_ = json.Unmarshal(w.Body.Bytes(), &report)
	if w.Code != 200 || len(report["formats"].([]any)) != 4 || strings.Contains(w.Body.String(), "fixture-only-password") {
		t.Fatal("conversion report contract", w.Body.String())
	}
	_ = s.repository.UpdateState("clash", func(p map[string]any) error { p["traffic"].(map[string]any)["expire"] = int64(1); return nil })
	for _, path := range []string{"/sub/" + slug, "/convert/" + slug + "/shadowrocket"} {
		w := get("GET", path)
		if w.Code != 403 || strings.Contains(w.Body.String(), "fixture-only-password") || w.Header().Get("Subscription-Userinfo") != "" {
			t.Fatal("expired subscription leaked nodes", w.Code, w.Body.String())
		}
	}
}
