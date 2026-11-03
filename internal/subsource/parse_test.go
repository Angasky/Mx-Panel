package subsource

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestClashNormalizationAndFields(t *testing.T) {
	text := `proxies:
 - {name: HY, type: hy2, server: hy.example.com, port: 24443, password: secret, sni: hy.example.com, skip-cert-verify: false, custom: {id: 9007199254740993}, dialer-proxy: foreign}
 - {name: HTTPS, type: https, server: web.example.com, port: 443}
 - {name: Snell, type: snell, server: snell.example.com, port: 24443, psk: 'a+b/c@d', version: 5, udp: true}
 - {name: Reality, type: vless, server: v.example.com, port: 443, uuid: '11111111-1111-4111-8111-111111111111', tls: true, reality-opts: {public-key: key, short-id: null, support-x25519mlkem768: false}}
 - {name: invalid, type: not-supported, server: invalid.example.com, port: 443}
 - invalid
`
	batch, err := Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	if len(batch.Nodes) != 4 || batch.SkippedCount != 2 {
		t.Fatal(batch)
	}
	hy := batch.Nodes[0]
	if hy["type"] != "hysteria2" || hy["sni"] != "hy.example.com" || hy["skip-cert-verify"] != false || hy["dialer-proxy"] != nil {
		t.Fatal("HY2 transport lost", hy)
	}
	if fmt.Sprint(hy["custom"].(map[string]any)["id"]) != "9007199254740993" {
		t.Fatal("integer rounded")
	}
	if batch.Nodes[1]["type"] != "http" || batch.Nodes[1]["tls"] != true || batch.Nodes[2]["psk"] != "a+b/c@d" {
		t.Fatal("protocol normalization failed")
	}
	if _, exists := batch.Nodes[3]["reality-opts"].(map[string]any)["short-id"]; exists {
		t.Fatal("empty short ID was retained")
	}
	if _, err := Parse(text + "---\nproxies: []\n"); err == nil {
		t.Fatal("multiple YAML documents accepted")
	}
}

func TestLinksAndBase64SnellPolicy(t *testing.T) {
	text := "[Proxy]\nHY2://password@hy.example.com:24443/?sni=hy.example.com#HY\nHK = snell, snell.example.com, 24443, psk=a+b/c@d, version=5, udp=true\nunknown://password@host:443\n"
	for _, content := range []string{text, base64.StdEncoding.EncodeToString([]byte(text)), base64.RawURLEncoding.EncodeToString([]byte(text))} {
		batch, err := Parse(content)
		if err != nil || len(batch.Nodes) != 2 || batch.SkippedCount != 1 {
			t.Fatal(batch, err)
		}
		if batch.Nodes[0]["password"] != "password" || batch.Nodes[1]["psk"] != "a+b/c@d" || batch.Nodes[1]["name"] != "HK" {
			t.Fatal("credentials changed", batch.Nodes)
		}
	}
}

func TestInvalidInputsAndBoundedDiagnostics(t *testing.T) {
	valid := "trojan://secret@host.example.com:443#A\n"
	batch, err := Parse(valid + strings.Repeat("password-leak-not-a-link\n", 100))
	if err != nil || batch.SkippedCount != 100 || len(batch.Skipped) != 30 || strings.Contains(strings.Join(batch.Skipped, ""), "password-leak") {
		t.Fatal(batch, err)
	}
	for _, content := range []string{"", "not a subscription", string([]byte{255}), strings.Repeat("x", MaxBytes+1), "proxies: []", `proxies: [{name: bad, type: snell, server: x, port: 1, version: 5}]`, `proxies: [{name: bad, type: vless, server: x, port: 443, uuid: '11111111-1111-4111-8111-111111111111', reality-opts: {short-id: abc}}]`} {
		if _, err := Parse(content); err == nil {
			t.Fatal("invalid subscription accepted")
		}
	}
}
