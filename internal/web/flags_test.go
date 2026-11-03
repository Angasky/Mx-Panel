package web

import (
	"context"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/geo"
)

func TestNativeCountryFlagsHTTPAndNetworkOutsideConfigLock(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	if err := s.repository.Mutate("clash", func(d config.Document) error {
		d["proxies"] = []any{config.Document{"name": "A", "type": "trojan", "server": "node.example.com", "port": 443, "password": "secret"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	calls := 0
	s.countryLookup = func(ctx context.Context, host string) (geo.Country, error) {
		calls++
		if err := s.repository.Mutate("clash", func(d config.Document) error { d["keep"] = "latest"; return nil }); err != nil {
			t.Error(err)
		}
		return geo.Country{Code: "US", IP: "8.8.8.8"}, nil
	}
	body := `{"names":["A"]}`
	if w := request(s, "POST", "/admin/api/nodes/flags", body, "", "https://panel.test", true); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if calls != 0 {
		t.Fatal("unauthenticated lookup")
	}
	w := request(s, "POST", "/admin/api/nodes/flags", body, token, "https://panel.test", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"updated":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	raw, _ := s.repository.Raw("clash")
	if !strings.Contains(raw, "latest") {
		t.Fatal("network-phase edit overwritten")
	}
}
