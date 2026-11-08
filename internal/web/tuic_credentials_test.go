package web

import (
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"strings"
	"testing"
)

func TestTUICQueryCredentialImportSaveAndShare(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	input := "tuic://11111111-1111-4111-8111-111111111111@example.net:443?password=fixture%3Asecret&congestion-controller=cubic&udp-relay-mode=quic#Legacy\n" +
		"tuic://11111111-1111-4111-8111-111111111111:private-secret@example.net:443?password=other#Bad"
	body, _ := json.Marshal(map[string]any{"links": input})
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct {
		Added  int
		Failed []any
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Added != 1 || len(result.Failed) != 1 {
		t.Fatal("unexpected import result", w.Code)
	}
	if strings.Contains(w.Body.String(), "private-secret") {
		t.Fatal("diagnostic leaked secret")
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=Legacy", "", token, "", true)
	var share struct{ URI string }
	if json.Unmarshal(w.Body.Bytes(), &share) != nil || w.Code != 200 {
		t.Fatal("sharing failed", w.Code)
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["password"] != "fixture:secret" || node["congestion-controller"] != "cubic" || node["udp-relay-mode"] != "quic" {
		t.Fatal("persisted parameters changed", err)
	}
}
