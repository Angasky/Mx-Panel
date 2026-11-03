package web

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestMieruHTTPBatchShareQRAndClientFiltering(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	if err := s.repository.Mutate("clash", func(d config.Document) error {
		d["proxy-groups"] = []any{config.Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	uri := "mierus://user:fixture-secret@example.com?profile=Mieru&port=2999&port=3000-3002&protocol=TCP&protocol=UDP"
	raw, _ := json.Marshal(map[string]any{"links": uri + "\n" + strings.Replace(uri, "protocol=UDP", "protocol=QUIC", 1) + "\n" + uri, "addToGroups": true})
	if w := request(s, "POST", "/admin/api/import-node", string(raw), "", "https://panel.test", true); w.Code != 401 {
		t.Fatal("unauthenticated import")
	}
	if w := request(s, "POST", "/admin/api/import-node", string(raw), token, "https://other.test", true); w.Code != 403 {
		t.Fatal("foreign origin import")
	}
	w := request(s, "POST", "/admin/api/import-node", string(raw), token, "https://panel.test", true)
	var result struct {
		Total, Added    int
		Failed, Renamed []any
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if w.Code != 200 || result.Total != 3 || result.Added != 4 || len(result.Failed) != 1 || len(result.Renamed) != 2 {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot, _ := s.repository.Snapshot("clash")
	nodes := snapshot["nodes"].([]any)
	if len(nodes) != 4 || nodes[1].(config.Document)["port"] != "3000-3002" {
		t.Fatal("range display lost")
	}
	group := snapshot["groups"].([]any)[0].(config.Document)["config"].(config.Document)
	if len(group["proxies"].([]any)) != 5 {
		t.Fatal("group membership lost")
	}
	name := nodes[1].(config.Document)["name"].(string)
	query := url.QueryEscape(name)
	w = request(s, "GET", "/admin/api/nodes/share?name="+query, "", token, "", true)
	var share struct{ URI string }
	json.Unmarshal(w.Body.Bytes(), &share)
	node, err := links.Parse(share.URI)
	if w.Code != 200 || err != nil || node["password"] != "fixture-secret" || node["port-range"] != "3000-3002" {
		t.Fatal("Mieru share changed credentials", w.Code, err)
	}
	w = request(s, "GET", "/admin/api/nodes/qrcode?name="+query, "", token, "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `fill="#fff"`) {
		t.Fatal("Mieru QR failed", w.Code)
	}
	if err = s.repository.Mutate("clash", func(d config.Document) error {
		return config.EditNode(d, "POST", config.Document{"config": config.Document{"name": "compatible", "type": "trojan", "server": "example.com", "port": 443, "password": "compatible-secret"}})
	}); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"v2rayn", "v2rayng", "v2ray", "shadowrocket"} {
		w = request(s, "GET", "/convert/"+strings.Repeat("a", 50)+"/"+format, "", "", "", true)
		body, err := base64.StdEncoding.DecodeString(w.Body.String())
		if w.Code != 200 || err != nil || strings.Contains(string(body), "mierus://") || w.Header().Get("X-Mxioc-Skipped-Nodes") != "4" {
			t.Fatal("Mieru leaked into unsupported client", format, w.Code)
		}
	}
	w = request(s, "GET", "/sub/"+strings.Repeat("a", 50), "", "", "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "port-range: 3000-3002") {
		t.Fatal("full YAML lost Mieru range")
	}
}
