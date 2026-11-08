package remote

import "testing"

func TestNodeOutboundRejectsLossyOptionsAndPreservesReality(t *testing.T) {
	node := Record{"name": "fixture", "type": "vless", "server": "example.com", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "tls": true, "flow": "xtls-rprx-vision", "servername": "www.example.com", "reality-opts": Record{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "abcd"}}
	out, err := NodeOutbound(node, "fixture")
	if err != nil {
		t.Fatal(err)
	}
	stream := out["streamSettings"].(Record)
	if stream["security"] != "reality" || stream["realitySettings"].(Record)["shortId"] != "abcd" {
		t.Fatal("Reality lost")
	}
	for key, value := range (Record{"dialer-proxy": "entry", "packet-encoding": "xudp", "skip-cert-verify": true, "udp": false, "smux": Record{"enabled": true}}) {
		copy := Record{}
		for k, v := range node {
			copy[k] = v
		}
		copy[key] = value
		if _, err = NodeOutbound(copy, "fixture"); err == nil {
			t.Fatal("unsupported option silently dropped", key)
		}
	}
}

func TestExplicitTLSVerificationPolicy(t *testing.T) {
	for _, kind := range []string{"http", "trojan", "vless", "vmess", "hysteria2", "tuic"} {
		for _, insecure := range []bool{false, true} {
			node := Record{"type": kind, "server": "example.net", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "password": "secret", "tls": true, "skip-cert-verify": insecure}
			if kind != "hysteria2" && kind != "tuic" {
				out, err := NodeOutbound(node, "proxy")
				if insecure {
					if err == nil {
						t.Fatal("unsupported Xray allowInsecure emitted")
					}
				} else if err != nil || out["streamSettings"].(Record)["tlsSettings"].(Record)["allowInsecure"] != insecure {
					t.Fatal(kind, out, err)
				}
			} else if kind == "hysteria2" {
				delete(node, "uuid")
			}
			out, err := singRelayOutbound(node, "proxy")
			if err != nil || out["tls"].(Record)["insecure"] != insecure {
				t.Fatal(kind, out, err)
			}
		}
	}
}
