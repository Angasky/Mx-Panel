package remote

import (
	"encoding/json"
	"testing"
)

func TestSingWebSocketOmitsEmptyHostWithoutChangingSource(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "trojan"} {
		for _, name := range []string{"Host", "host", "HOST"} {
			for _, host := range []string{"", "ws.example.com"} {
				node := Record{"name": "ws", "type": kind, "server": "node.example.com", "port": 443, "uuid": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "password": "fixture-password", "tls": true, "servername": "node.example.com", "network": "ws", "ws-opts": Record{"path": "/vpn", "headers": Record{name: host, "X-Test": "keep"}}}
				before, _ := json.Marshal(node)
				out, err := singRelayOutbound(node, "proxy")
				if err != nil {
					t.Fatal(err)
				}
				headers := out["transport"].(Record)["headers"].(Record)
				if headers["X-Test"] != "keep" {
					t.Fatal("unrelated header lost")
				}
				if host == "" {
					if _, exists := headers[name]; exists {
						t.Fatal("empty Host emitted")
					}
				} else if headers[name] != host {
					t.Fatal("custom Host lost")
				}
				after, _ := json.Marshal(node)
				if string(before) != string(after) {
					t.Fatal("conversion changed source node")
				}
			}
		}
	}
}
