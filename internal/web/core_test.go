package web

import (
	"github.com/Angasky/dingzhi-ban/internal/config"
	"strings"
	"testing"
)

func TestCoreRoutesEnforceAuthenticationOriginAndBindingGuard(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	body := `{"serverId":"fixture","version":"` + strings.Repeat("a", 64) + `","config":{}}`
	if w := request(s, "GET", "/admin/api/servers/core?id=fixture", "", "", "", true); w.Code != 401 {
		t.Fatal("config disclosed")
	}
	if w := request(s, "PUT", "/admin/api/servers/core", body, token, "https://other.test", true); w.Code != 403 {
		t.Fatal("foreign origin write")
	}
	if w := request(s, "PUT", "/admin/api/servers/core", `{}`, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("missing identity accepted")
	}
	if err := s.repository.UpdateState("clash", func(p config.Document) error {
		p["remoteNodes"] = []any{config.Document{"serverId": "fixture", "status": "active"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w := request(s, "PUT", "/admin/api/servers/core", body, token, "https://panel.test", true)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "禁止整份配置覆盖") {
		t.Fatal(w.Code, w.Body.String())
	}
}
