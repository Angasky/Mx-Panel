package web

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
	"go.yaml.in/yaml/v3"
)

func TestHTTPProxyImportShareAndMihomoSubscription(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	input := "https://user:p%40ss@example.net?host=cdn.example&user-agent=Agent%20One&sni=tls.example&name-cert-verify=cert.example&fingerprint=" + strings.Repeat("ab", 32) + "#HTTPS\n" +
		"http://example.net?ua=Agent#Plain\n" +
		"http://example.net?host=ok%0d%0aInjected%3Asecret#Invalid"
	body, _ := json.Marshal(map[string]any{"links": input})
	for _, check := range []struct {
		token, origin string
		status        int
	}{{"", "https://panel.test", 401}, {token, "https://other.test", 403}} {
		if w := request(s, "POST", "/admin/api/import-node", string(body), check.token, check.origin, true); w.Code != check.status {
			t.Fatal("access control failed", w.Code)
		}
	}
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct {
		Added  int
		Failed []any
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || w.Code != 200 || result.Added != 2 || len(result.Failed) != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "Injected") {
		t.Fatal("invalid header leaked")
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=HTTPS", "", token, "", true)
	var share struct{ URI string }
	if err := json.Unmarshal(w.Body.Bytes(), &share); err != nil || w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["name-cert-verify"] != "cert.example" || node["headers"].(map[string]any)["User-Agent"] != "Agent One" || node["fingerprint"] == nil {
		t.Fatal("saved share options lost", err)
	}
	w = request(s, "GET", "/sub/"+strings.Repeat("a", 50), "", "", "", true)
	var doc struct {
		Proxies []map[string]any `yaml:"proxies"`
	}
	if w.Code != 200 || yaml.Unmarshal(w.Body.Bytes(), &doc) != nil || len(doc.Proxies) != 2 {
		t.Fatal("subscription failed", w.Code, w.Body.String())
	}
	for _, n := range doc.Proxies {
		if n["name"] == "HTTPS" && (n["fingerprint"] != node["fingerprint"] || n["name-cert-verify"] != "cert.example" || n["headers"].(map[string]any)["Host"] != "cdn.example") {
			t.Fatal("YAML lost proxy options")
		}
	}
}
