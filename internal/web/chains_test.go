package web

import (
	"github.com/Angasky/dingzhi-ban/internal/config"
	"testing"
)

func TestChainHTTPAuthenticationAndContract(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, path := range []string{"/admin/api/failovers", "/admin/api/server-chains"} {
		if w := request(s, "GET", path, "", "", "", true); w.Code != 401 {
			t.Fatal("chain metadata disclosed", w.Code)
		}
		if w := request(s, "GET", path, "", token, "", true); w.Code != 200 {
			t.Fatal("chain page dependency", w.Code, w.Body.String())
		}
	}
	err := s.repository.Mutate("clash", func(doc config.Document) error {
		doc["proxies"] = []any{config.Document{"name": "entry", "type": "trojan", "server": "a.example.com", "port": 443, "password": "test"}, config.Document{"name": "exit", "type": "trojan", "server": "b.example.com", "port": 443, "password": "test"}}
		doc["proxy-groups"] = []any{config.Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}}}
		doc["rules"] = []any{"MATCH,Proxy"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	body := `{"name":"chain","entry":"entry","exit":"exit","mode":"mihomo","groups":["Proxy"]}`
	if w := request(s, "POST", "/admin/api/chains", body, "", "https://panel.test", true); w.Code != 401 {
		t.Fatal("missing login", w.Code)
	}
	if w := request(s, "POST", "/admin/api/chains", body, token, "https://other.test", true); w.Code != 403 {
		t.Fatal("cross origin", w.Code)
	}
	if w := request(s, "POST", "/admin/api/chains", body, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(s, "PUT", "/admin/api/chains", `{"oldName":"chain","name":"renamed","entry":"entry","exit":"exit","groups":[]}`, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 3 {
		t.Fatal("chain not persisted", err)
	}
}
