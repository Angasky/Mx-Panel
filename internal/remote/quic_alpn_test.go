package remote

import (
	"maps"
	"reflect"
	"testing"
)

func TestLegacyQUICALPNSingConversion(t *testing.T) {
	for _, kind := range []string{"hysteria2", "tuic"} {
		node := Record{"type": kind, "server": "node.example.net", "port": 443, "password": "fixture-secret", "alpn": "custom"}
		if kind == "tuic" {
			node["uuid"] = "11111111-1111-4111-8111-111111111111"
		}
		before := maps.Clone(node)
		out, err := singRelayOutbound(node, "proxy")
		if err != nil || !reflect.DeepEqual(out["tls"].(Record)["alpn"], []any{"custom"}) {
			t.Fatal("native ALPN changed", err)
		}
		if !reflect.DeepEqual(node, before) {
			t.Fatal("source changed")
		}
		for _, raw := range []any{nil, 3, []any{"h3", false}, "custom,h3"} {
			node["alpn"] = raw
			if _, err := singRelayOutbound(node, "proxy"); err == nil {
				t.Fatal("invalid ALPN accepted")
			}
		}
	}
}
