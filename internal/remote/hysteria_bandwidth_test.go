package remote

import (
	"encoding/json"
	"maps"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestLegacyQUICSubscriptionToSingBox(t *testing.T) {
	var batch struct {
		Nodes []Record `yaml:"proxies"`
	}
	err := yaml.Unmarshal([]byte(`proxies:
  - name: legacy-hy2
    type: hysteria2
    server: landing.example.net
    port: 443
    password: fixture-secret
    sni: landing.example.net
    up: 50 Mbps
    down: 100 Mbps
  - name: legacy-tuic
    type: tuic
    server: landing.example.net
    port: 443
    uuid: 11111111-1111-4111-8111-111111111111
    password: fixture-secret
    servername: landing.example.net
`), &batch)
	if err != nil || len(batch.Nodes) != 2 {
		t.Fatal("legacy YAML rejected", err)
	}
	for _, node := range batch.Nodes {
		before := maps.Clone(node)
		out, err := singRelayOutbound(node, "landing")
		if err != nil {
			t.Fatal(err)
		}
		tls := out["tls"].(Record)
		if tls["enabled"] != true || tls["server_name"] != "landing.example.net" || tls["insecure"] == true {
			t.Fatal("TLS semantics changed")
		}
		if node["type"] == "hysteria2" && (out["up_mbps"] != 50 || out["down_mbps"] != 100) {
			t.Fatal("bandwidth lost")
		}
		if !reflect.DeepEqual(node, before) {
			t.Fatal("source node mutated")
		}
	}
}

func TestLegacyHysteriaBandwidthRepresentations(t *testing.T) {
	for _, raw := range []any{"50", "50 Mbps", "50Mbps", 50, int64(50), float64(50), json.Number("50")} {
		got, err := legacyHysteriaMbps(raw)
		if err != nil || got != 50 {
			t.Fatal("valid rate rejected", err)
		}
	}
	base := Record{"type": "hysteria2", "server": "landing.example.net", "port": 443, "password": "fixture-secret"}
	for _, raw := range []any{nil, true, "", "0", -1, "1.5 Mbps", 1.5, "50 MBps", "50 Kbps", "50 Mbps junk", "50\nMbps", "2147483648", []any{50}, Record{"rate": 50}} {
		node := maps.Clone(base)
		node["up"] = raw
		if _, err := singRelayOutbound(node, "landing"); err == nil {
			t.Fatalf("unsupported rate accepted (%T)", raw)
		}
	}
	for _, patch := range []Record{
		{"servername": nil}, {"servername": 50}, {"sni": true}, {"tls": false}, {"tls": nil}, {"tls": "true"}, {"skip-cert-verify": "true"},
		{"sni": "one.example.net", "servername": "two.example.net"},
	} {
		node := maps.Clone(base)
		maps.Copy(node, patch)
		if _, err := singRelayOutbound(node, "landing"); err == nil {
			t.Fatal("ambiguous or insecure TLS accepted")
		}
	}
}
