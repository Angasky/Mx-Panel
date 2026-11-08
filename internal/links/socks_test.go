package links

import (
	"reflect"
	"testing"
)

func TestSOCKSPythonDefaultsAndRoundTrip(t *testing.T) {
	for _, uri := range []string{"socks://example.net#Default", "socks5://user:p%40ss%3Aword@[2001:db8::1]?udp=false&tls=true&servername=tls.example&skip-cert-verify=false#TLS", "socks5://example.net:1081?udp=false#NoAuth", "socks5://user@example.net?tls=true&allowInsecure=1#UserOnly"} {
		node, err := Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		shared, err := Export(node)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Parse(shared)
		if err != nil || !reflect.DeepEqual(node, restored) {
			t.Fatal("SOCKS settings lost", uri, err, node, restored)
		}
	}
	for _, uri := range []string{"socks://example.net:", "socks://example.net?udp=invalid", "socks://example.net?udp=false&udp=true", "socks://example.net?tls=true&security=none", "socks://example.net?security=tls&tls=false", "socks://example.net?tls=true&sni=a&servername=b", "socks://example.net?tls=true&skip-cert-verify=false&insecure=1", "socks://example.net?host=proxy.example"} {
		if _, err := Parse(uri); err == nil {
			t.Fatal("ambiguous SOCKS settings accepted", uri)
		}
	}
	node := map[string]any{"type": "socks5", "server": "example.net", "port": 1080, "udp": false, "headers": map[string]any{"Host": "proxy.example"}}
	if _, err := Export(node); err == nil {
		t.Fatal("unsupported SOCKS option dropped")
	}
}
