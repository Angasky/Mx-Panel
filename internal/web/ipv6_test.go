package web

import (
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"strings"
	"testing"
)

func TestLegacyIPv6ImportPersistsAndSharesCanonicalAuthority(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	body, _ := json.Marshal(map[string]any{"links": "trojan://fixture%3Asecret@2001:db8::1:443#IPv6"})
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct{ Added int }
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Added != 1 {
		t.Fatal("IPv6 import failed", w.Code)
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=IPv6", "", token, "", true)
	var share struct{ URI string }
	if json.Unmarshal(w.Body.Bytes(), &share) != nil || w.Code != 200 || !strings.Contains(share.URI, "[2001:db8::1]:443") {
		t.Fatal("canonical share failed", w.Code)
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["server"] != "2001:db8::1" || node["password"] != "fixture:secret" {
		t.Fatal("saved IPv6 node changed", err)
	}
}
