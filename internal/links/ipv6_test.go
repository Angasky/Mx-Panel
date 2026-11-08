package links

import (
	"reflect"
	"strings"
	"testing"
)

func TestPythonUnbracketedIPv6RoundTrip(t *testing.T) {
	for _, prefix := range []string{
		"vless://11111111-1111-4111-8111-111111111111@",
		"trojan://pass%3Aword%40value@", "hy2://pass%3Aword@",
		"tuic://11111111-1111-4111-8111-111111111111:pass%3Aword@",
		"socks5://user:pass%40word@", "http://user:pass%3Aword@", "https://user:pass%40word@",
		"ss://YWVzLTEyOC1nY206c2VjcmV0@",
	} {
		for _, host := range []string{"2001:db8::1", "::1", "::ffff:192.0.2.1"} {
			suffix := ":443#IPv6%20%E8%8A%82%E7%82%B9"
			node, err := Parse(prefix + host + suffix)
			if err != nil {
				t.Fatal("legacy IPv6 rejected", err)
			}
			canonical, err := Parse(prefix + "[" + host + "]" + suffix)
			if err != nil || !reflect.DeepEqual(node, canonical) {
				t.Fatal("authority normalization changed node", err)
			}
			shared, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(shared, "["+host+"]:443") {
				t.Fatal("export lacks canonical IPv6 authority")
			}
			restored, err := Parse(shared)
			if err != nil || !reflect.DeepEqual(node, restored) {
				t.Fatal("IPv6 roundtrip changed settings", err)
			}
		}
	}
	uri := "https://u:p%3A%40@2001:db8::1:443/?sni=tls.example&host=cdn.example#named"
	normalized, err := normalizeIPv6Authority(uri)
	if err != nil || normalized != "https://u:p%3A%40@[2001:db8::1]:443/?sni=tls.example&host=cdn.example#named" {
		t.Fatal("query or credential rewritten", err)
	}
}

func TestInvalidLegacyIPv6IsRejected(t *testing.T) {
	for _, endpoint := range []string{"not:ipv6:443", "2001:db8::1:", "2001:db8::1:0", "2001:db8::1:65536", "2001:db8::1:+443", "2001:db8::1:port", "2001:db8::1%25eth0:443"} {
		if _, err := Parse("http://user:secret@" + endpoint); err == nil {
			t.Fatal("invalid authority accepted")
		}
	}
	for _, uri := range []string{"http://example.net", "https://[2001:db8::1]", "socks5://user:p%40ss@example.net:1080"} {
		got, err := normalizeIPv6Authority(uri)
		if err != nil || got != uri {
			t.Fatal("standard authority changed", err)
		}
	}
}
