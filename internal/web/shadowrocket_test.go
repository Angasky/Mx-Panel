package web

import (
	"github.com/Angasky/dingzhi-ban/internal/config"
	"strings"
	"testing"
)

func TestRocketPublicPairedConfigAndExpiredAccess(t *testing.T) {
	s := fixture(t)
	if err := s.repository.Mutate("clash", func(d config.Document) error {
		d["proxies"] = []any{config.Document{"name": "one", "type": "trojan", "server": "a.example.com", "port": 443, "password": "first-secret"}, config.Document{"name": "two", "type": "trojan", "server": "b.example.com", "port": 443, "password": "second-secret"}}
		d["proxy-groups"] = []any{config.Document{"name": "HA", "type": "fallback", "proxies": []any{"one", "two"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := s.repository.UpdateState("clash", func(p config.Document) error {
		p["failovers"] = []any{config.Document{"name": "HA", "status": "active", "exit": "fixed", "interval": 30, "paths": []any{"one", "two"}}}
		p["serverChains"] = []any{config.Document{"name": "one", "serverId": "a", "inboundId": 1, "exit": "fixed"}, config.Document{"name": "two", "serverId": "b", "inboundId": 2, "exit": "fixed"}}
		p["remoteNodes"] = []any{config.Document{"serverId": "a", "inboundId": 1, "status": "active", "pendingUser": "must-not-leak"}, config.Document{"serverId": "b", "inboundId": 2, "status": "active"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	base := "/convert/" + strings.Repeat("a", 50) + "/"
	for _, format := range []string{"shadowrocket-ha", "shadowrocket-config"} {
		w := request(s, "GET", base+format, "", "", "", true)
		if w.Code != 200 || strings.Contains(w.Body.String(), "must-not-leak") {
			t.Fatal(w.Code, w.Body.String())
		}
		head := request(s, "HEAD", base+format, "", "", "", true)
		if head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") != w.Header().Get("Content-Length") {
			t.Fatal("HEAD mismatch")
		}
		if format == "shadowrocket-config" && (!strings.Contains(w.Header().Get("Content-Disposition"), ".conf") || !strings.Contains(w.Body.String(), "FINAL,MX-Select")) {
			t.Fatal("policy contract mismatch")
		}
	}
	if err := s.repository.UpdateState("clash", func(p config.Document) error { p["accessRevoked"] = true; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"shadowrocket-ha", "shadowrocket-config"} {
		if w := request(s, "GET", base+format, "", "", "", true); w.Code != 403 {
			t.Fatal("revoked HA export allowed")
		}
	}
}
