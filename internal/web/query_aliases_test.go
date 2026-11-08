package web

import (
	"encoding/json"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestLegacyQueryAliasImportAndShare(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	input := "vless://11111111-1111-4111-8111-111111111111@example.net:443?security=tls&network=grpc&peer=tls.example&service_name=vpn#Legacy\n" +
		"trojan://fixture-secret@example.net:443?type=ws&network=grpc#Conflict"
	body, _ := json.Marshal(map[string]any{"links": input})
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct {
		Added  int
		Failed []any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Added != 1 || len(result.Failed) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=Legacy", "", token, "", true)
	var share struct{ URI string }
	if err := json.Unmarshal(w.Body.Bytes(), &share); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["servername"] != "tls.example" || node["network"] != "grpc" || node["grpc-opts"].(map[string]any)["grpc-service-name"] != "vpn" {
		t.Fatal("saved and shared transport changed", err)
	}
}
