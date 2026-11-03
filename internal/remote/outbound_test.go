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
