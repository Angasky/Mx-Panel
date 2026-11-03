package web

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func TestCertificateHTTPContractsAndAuthentication(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	m, err := s.remoteManager()
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.Save(remote.Record{"name": "test", "host": "192.0.2.1", "sshPassword": "test-password", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "panelPassword": "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"serverId": record["id"], "serverName": "node.example.com"})
	for _, auth := range []string{"", token} {
		origin := "https://panel.test"
		want := 401
		if auth != "" {
			origin = "https://other.test"
			want = 403
		}
		w := request(s, "POST", "/admin/api/servers/certificates", string(body), auth, origin, true)
		if w.Code != want {
			t.Fatal("certificate request bypassed auth/origin", w.Code)
		}
	}
	for _, path := range []string{"/admin/api/servers/certificates?id=unknown&job=unknown", "/admin/api/servers/certificates"} {
		if w := request(s, "GET", path, "", "", "", true); w.Code != 401 {
			t.Fatal("job disclosure without auth", w.Code)
		}
		if w := request(s, "GET", path, "", token, "", true); w.Code != 400 {
			t.Fatal("missing job accepted", w.Code)
		}
	}
	if w := request(s, "PUT", "/admin/api/servers/certificates", string(body), token, "https://panel.test", true); w.Code != 405 {
		t.Fatal("unsupported method", w.Code)
	}
	if w := request(s, "POST", "/admin/api/servers/certificates", `{"serverId":"unknown","serverName":"x.example;id"}`, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("invalid certificate input", w.Code)
	}
	// No background network task may outlive a stopped native service.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	m.SetJobContext(ctx)
	if w := request(s, "POST", "/admin/api/servers/certificates", string(body), token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("job started during shutdown", w.Code)
	}
	// A damaged encrypted credential fails in the worker before any network IO.
	m.SetJobContext(context.Background())
	file := filepath.Join(s.options.Root, "remote", "servers.json")
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var index map[string]any
	if json.Unmarshal(raw, &index) != nil {
		t.Fatal("registry fixture")
	}
	index["servers"].([]any)[0].(map[string]any)["sshPassword"] = "invalid-encrypted-credential"
	raw, _ = json.Marshal(index)
	if err = os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	w := request(s, "POST", "/admin/api/servers/certificates", string(body), token, "https://panel.test", true)
	if w.Code != 202 {
		t.Fatal("certificate start contract", w.Code, w.Body.String())
	}
	var accepted map[string]any
	if json.Unmarshal(w.Body.Bytes(), &accepted) != nil {
		t.Fatal("start JSON")
	}
	identity := accepted["job"].(map[string]any)["id"].(string)
	terminal := false
	for i := 0; i < 100; i++ {
		w = request(s, "GET", "/admin/api/servers/certificates?id="+record["id"].(string)+"&job="+identity, "", token, "", true)
		if w.Code != 200 {
			t.Fatal("poll contract", w.Code, w.Body.String())
		}
		var result map[string]any
		json.Unmarshal(w.Body.Bytes(), &result)
		if result["job"].(map[string]any)["status"] == "failed" {
			terminal = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !terminal {
		t.Fatal("failed credential did not reach terminal status")
	}
}
