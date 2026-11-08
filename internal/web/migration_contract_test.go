package web

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

// This is an inventory routing check, not a claim of business parity. Malformed
// write bodies prevent network calls and mutations; operation tests cover those.
func TestPythonMethodInventoryRouting(t *testing.T) {
	raw, err := os.ReadFile("../../docs/go/api-method-inventory.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory struct {
		Routes []struct{ Method, Path string }
	}
	if json.Unmarshal(raw, &inventory) != nil {
		t.Fatal("invalid inventory")
	}
	s := fixture(t)
	token := login(t, s)
	exceptions := map[string]string{
		"POST /admin/api/updates/check": "external GitHub call tested through update tests",
	}
	for _, route := range inventory.Routes {
		key := route.Method + " " + route.Path
		t.Run(key, func(t *testing.T) {
			if reason := exceptions[key]; reason != "" {
				t.Skip(reason)
			}
			if route.Path == "/clash" {
				return
			}
			// Logout invalidates the token and is covered independently.
			if route.Path == "/admin/api/logout" {
				return
			}
			w := request(s, route.Method, route.Path, "{", token, "https://panel.test", true)
			if w.Code == 404 || w.Code == 405 {
				t.Errorf("missing Python route: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestBulkDeletePythonContractAndAtomicity(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	reset := func() {
		t.Helper()
		if err := s.repository.Mutate("clash", func(d config.Document) error {
			d["proxies"] = []any{config.Document{"name": "A", "type": "http", "server": "a.example", "port": 80}, config.Document{"name": "B", "type": "http", "server": "b.example", "port": 80, "dialer-proxy": "A"}}
			d["proxy-groups"] = []any{config.Document{"name": "Proxy", "type": "select", "proxies": []any{"A", "B", "DIRECT"}}}
			d["rules"] = []any{"DOMAIN,a.example,A", "MATCH,Proxy"}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	reset()
	for _, body := range []string{`{"names":["A"]}`, `{"names":["A","missing"]}`, `{"names":[]}`, `{"names":["  "]}`, `{"names":[12]}`} {
		w := request(s, "DELETE", "/admin/api/nodes/bulk", body, token, "https://panel.test", true)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
		snap, _ := s.repository.Snapshot("clash")
		if len(snap["nodes"].([]any)) != 2 {
			t.Fatal("failed deletion partially persisted")
		}
	}
	for _, method := range []string{"DELETE", "POST"} {
		reset()
		w := request(s, method, "/admin/api/nodes/bulk", `{"names":[" B ","A","B", "  "]}`, token, "https://panel.test", true)
		var result struct {
			Deleted int
			Names   []string
		}
		if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Deleted != 2 || strings.Join(result.Names, ",") != "A,B" {
			t.Fatal(w.Code, w.Body.String())
		}
		snap, _ := s.repository.Snapshot("clash")
		if len(snap["nodes"].([]any)) != 0 {
			t.Fatal("nodes retained")
		}
	}
}

func TestHEADMatchesGETWithoutBodies(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, path := range []string{"/", "/admin/", "/healthz", "/admin/api/account", "/admin/api/snapshot", "/admin/api/raw", "/sub/" + strings.Repeat("a", 50), "/does-not-exist"} {
		for _, auth := range []string{"", token} {
			get := request(s, "GET", path, "", auth, "", true)
			head := request(s, "HEAD", path, "", auth, "", true)
			if head.Code != get.Code || head.Body.Len() != 0 || head.Header().Get("Content-Type") != get.Header().Get("Content-Type") {
				t.Fatalf("HEAD %s mismatch: %d/%d body %d", path, head.Code, get.Code, head.Body.Len())
			}
		}
	}
}

func TestPythonNodeCreateDefaultGroupMembership(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	if err := s.repository.Mutate("clash", func(d config.Document) error {
		d["proxies"] = []any{}
		d["proxy-groups"] = []any{
			config.Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}},
			config.Document{"name": "HA", "type": "fallback", "proxies": []any{"DIRECT"}},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, body := range []string{
		`{"config":{"name":"default","type":"http","server":"example.com","port":80}}`,
		`{"config":{"name":"excluded","type":"http","server":"example.com","port":80},"addToGroups":false}`,
	} {
		w := request(s, "POST", "/admin/api/nodes", body, token, "https://panel.test", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range snapshot["groups"].([]any) {
		group := raw.(config.Document)["config"].(config.Document)
		members := group["proxies"].([]any)
		if group["name"] == "Proxy" {
			if len(members) != 2 || members[1] != "default" {
				t.Fatal(group)
			}
		} else if len(members) != 1 {
			t.Fatal("fallback changed", group)
		}
	}
}
