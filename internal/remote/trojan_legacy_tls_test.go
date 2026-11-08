package remote

import (
	"maps"
	"reflect"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestLegacyTrojanImplicitTLS(t *testing.T) {
	var node Record
	if err := yaml.Unmarshal([]byte(`name: legacy
type: trojan
server: node.example.net
port: 443
password: fixture-secret
sni: tls.example.net
alpn: [h2, http/1.1]
client-fingerprint: chrome
`), &node); err != nil {
		t.Fatal(err)
	}
	for _, network := range []string{"tcp", "ws", "grpc"} {
		n := maps.Clone(node)
		n["network"] = network
		if network == "ws" {
			n["ws-opts"] = Record{"path": "/legacy"}
		}
		if network == "grpc" {
			n["grpc-opts"] = Record{"grpc-service-name": "legacy"}
		}
		before := maps.Clone(n)
		for _, kind := range []string{"xray", "sing-box"} {
			convert := NodeOutbound
			if kind == "sing-box" {
				convert = singRelayOutbound
			}
			out, err := convert(n, "proxy")
			if err != nil {
				t.Fatal(kind, network, err)
			}
			if kind == "xray" {
				stream := out["streamSettings"].(Record)
				tls := stream["tlsSettings"].(Record)
				if stream["security"] != "tls" || tls["serverName"] != "tls.example.net" || tls["fingerprint"] != "chrome" || !reflect.DeepEqual(tls["alpn"], node["alpn"]) {
					t.Fatal("implicit TLS lost settings")
				}
			} else {
				tls := out["tls"].(Record)
				if tls["enabled"] != true || tls["server_name"] != "tls.example.net" || tls["utls"].(Record)["fingerprint"] != "chrome" || !reflect.DeepEqual(tls["alpn"], node["alpn"]) {
					t.Fatal("sing TLS lost settings")
				}
			}
			explicit := maps.Clone(n)
			explicit["tls"] = true
			want, err := convert(explicit, "proxy")
			if err != nil || !reflect.DeepEqual(out, want) {
				t.Fatal("implicit and explicit TLS differ", err)
			}
		}
		if !reflect.DeepEqual(n, before) {
			t.Fatal("source mutated")
		}
	}
	for _, raw := range []any{false, nil, "true", 0} {
		n := maps.Clone(node)
		n["tls"] = raw
		if _, err := NodeOutbound(n, "proxy"); err == nil {
			t.Fatal("invalid TLS/SNI combination accepted")
		}
	}
	node["skip-cert-verify"] = "true"
	if _, err := NodeOutbound(node, "proxy"); err == nil {
		t.Fatal("verification bypass accepted")
	}
}

func TestTrojanTLSDefaultDoesNotChangeOtherProtocols(t *testing.T) {
	for _, kind := range []string{"trojan", "vmess", "vless", "http", "socks5", "ss"} {
		node := Record{"type": kind, "server": "node.test", "port": 443, "password": "fixture-secret", "uuid": "11111111-1111-4111-8111-111111111111", "cipher": "aes-128-gcm"}
		if kind == "vmess" {
			node["cipher"] = "auto"
		}
		out, err := NodeOutbound(node, "proxy")
		if err != nil {
			t.Fatal(err)
		}
		want := "none"
		if kind == "trojan" {
			want = "tls"
		}
		if out["streamSettings"].(Record)["security"] != want {
			t.Fatal("wrong default", kind)
		}
		node["tls"] = false
		out, err = NodeOutbound(node, "proxy")
		if err != nil || out["streamSettings"].(Record)["security"] != "none" {
			t.Fatal("explicit plaintext changed", kind, err)
		}
	}
}
