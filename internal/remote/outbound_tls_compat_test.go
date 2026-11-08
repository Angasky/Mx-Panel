package remote

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

func TestOutboundRealitySNIAliasAndConflicts(t *testing.T) {
	base := Record{"type": "vless", "server": "example.net", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "tls": true, "sni": "tls.example.net", "reality-opts": Record{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "abcd"}}
	for _, convert := range []func(Record, string) (Record, error){NodeOutbound, singRelayOutbound} {
		original := maps.Clone(base)
		out, err := convert(base, "proxy")
		if err != nil {
			t.Fatal(err)
		}
		if stream, ok := out["streamSettings"].(Record); ok {
			if stream["realitySettings"].(Record)["serverName"] != "tls.example.net" {
				t.Fatal("Reality SNI lost")
			}
		} else if out["tls"].(Record)["server_name"] != "tls.example.net" {
			t.Fatal("sing Reality SNI lost")
		}
		if !reflect.DeepEqual(base, original) {
			t.Fatal("source mutated")
		}
		for _, bad := range []any{"other.example.net", nil, 12, "bad\r\nname"} {
			node := maps.Clone(base)
			node["servername"] = bad
			if _, err = convert(node, "proxy"); err == nil {
				t.Fatal("conflicting or invalid SNI accepted", bad)
			}
		}
	}
}

func TestOutboundALPNValidationAndCopy(t *testing.T) {
	for _, convert := range []func(Record, string) (Record, error){NodeOutbound, singRelayOutbound} {
		for _, raw := range []any{[]string{"h2", "http/1.1"}, []any{"h2", "http/1.1"}, []any{}} {
			node := Record{"type": "trojan", "server": "example.net", "port": 443, "password": "secret", "alpn": raw}
			out, err := convert(node, "proxy")
			if err != nil {
				t.Fatal(err)
			}
			tls, _ := out["tls"].(Record)
			if tls == nil {
				tls = out["streamSettings"].(Record)["tlsSettings"].(Record)
			}
			list := tls["alpn"].([]any)
			if len(list) > 0 {
				list[0] = "changed"
				if reflect.DeepEqual(node["alpn"], list) {
					t.Fatal("output aliases stored ALPN")
				}
			}
		}
		for _, raw := range []any{nil, "h2", []any{""}, []any{"h2,http/1.1"}, []any{"h2\n"}, []any{strings.Repeat("x", 256)}, []any{true}} {
			if _, err := convert(Record{"type": "trojan", "server": "example.net", "port": 443, "password": "secret", "alpn": raw}, "proxy"); err == nil {
				t.Fatal("invalid ALPN accepted", raw)
			}
		}
	}
}
