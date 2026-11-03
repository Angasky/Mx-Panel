package web

import (
	"strings"
	"testing"
)

func TestSNIHTTPAuthenticationAndValidation(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, tc := range []struct {
		token, origin string
		secure        bool
		status        int
	}{
		{"", "https://panel.test", true, 401}, {token, "https://other.test", true, 403}, {token, "https://panel.test", false, 426},
	} {
		w := request(s, "POST", "/admin/api/servers/sni", `{"serverId":"unknown","candidates":["www.example.com"]}`, tc.token, tc.origin, tc.secure)
		if w.Code != tc.status {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	for _, body := range []string{`{}`, `[]`, `{"serverId":"unknown","candidates":"example.com"}`, `{"serverId":"unknown","candidates":[1]}`, `{"serverId":"unknown","candidates":["https://example.com"]}`, `{"serverId":"unknown","candidates":["www.example.com"],"force":"yes"}`, `{"serverId":"unknown","candidates":["www.example.com"]}`} {
		w := request(s, "POST", "/admin/api/servers/sni", body, token, "https://panel.test", true)
		if w.Code != 400 || strings.Contains(w.Body.String(), "fingerprint") {
			t.Fatal("invalid scan request accepted", w.Code, w.Body.String())
		}
	}
	if w := request(s, "GET", "/admin/api/servers/sni", "", token, "", true); w.Code != 405 {
		t.Fatal("wrong method accepted", w.Code)
	}
}
