package links

import "testing"

func TestWebSocketURIOmitsUnspecifiedHost(t *testing.T) {
	for _, scheme := range []string{"vless", "trojan"} {
		for _, query := range []string{"", "&host=", "&host=ws.example.com"} {
			uri := scheme + "://fixture-password@node.example.com:443?security=tls&type=ws&path=%2Fvpn" + query
			node, err := Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			headers := node["ws-opts"].(map[string]any)["headers"].(map[string]any)
			if query == "&host=ws.example.com" {
				if headers["Host"] != "ws.example.com" {
					t.Fatal("custom Host lost")
				}
			} else if _, exists := headers["Host"]; exists {
				t.Fatal("missing Host became empty HTTP header")
			}
			out, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(out)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip := restored["ws-opts"].(map[string]any)["headers"].(map[string]any)
			if roundtrip["Host"] != headers["Host"] {
				t.Fatal("round trip changed Host")
			}
		}
	}
}
