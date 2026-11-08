package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestCertificatePinsPersistThroughImportShareAndSubscription(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	pin := strings.Repeat("AB", 32)
	input := "hysteria2://secret@example.net:443?pinSHA256=" + pin + "#PinnedHY2\n" +
		"tuic://11111111-1111-4111-8111-111111111111:secret@example.net:443?pinned_certchain_sha256=" + pin + "#PinnedTUIC\n" +
		"hysteria2://secret@example.net:443?pinSHA256=invalid#Invalid"
	raw, _ := json.Marshal(map[string]any{"links": input})
	w := request(s, "POST", "/admin/api/import-node", string(raw), token, "https://panel.test", true)
	var result struct {
		Added  int
		Failed []any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Added != 2 || len(result.Failed) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, name := range []string{"PinnedHY2", "PinnedTUIC"} {
		w = request(s, "GET", "/admin/api/nodes/share?name="+name, "", token, "", true)
		var share struct{ URI string }
		if err := json.Unmarshal(w.Body.Bytes(), &share); err != nil || w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
		node, err := links.Parse(share.URI)
		if err != nil || strings.ReplaceAll(node["fingerprint"].(string), ":", "") != pin {
			t.Fatal("share lost pin", err)
		}
	}
	w = request(s, "GET", "/sub/"+strings.Repeat("a", 50), "", "", "", true)
	if w.Code != 200 || strings.Count(w.Body.String(), "fingerprint:") != 2 || !strings.Contains(w.Body.String(), "AB:AB:AB") {
		t.Fatal("Mihomo subscription lost certificate pins", w.Code, w.Body.String())
	}
}
