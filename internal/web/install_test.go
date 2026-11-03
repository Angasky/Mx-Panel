package web

import "testing"

func TestInstallRoutesRequireAuthenticationAndOrigin(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	if w := request(s, "GET", "/admin/api/servers/jobs?id=fixture", "", "", "", true); w.Code != 401 {
		t.Fatal("job log disclosed")
	}
	if w := request(s, "POST", "/admin/api/servers/install", `{"id":"fixture","confirmed":true}`, token, "https://other.test", true); w.Code != 403 {
		t.Fatal("foreign origin install")
	}
	if w := request(s, "POST", "/admin/api/servers/install", `{}`, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("invalid install accepted")
	}
}
