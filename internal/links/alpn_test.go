package links

import (
	"maps"
	"reflect"
	"strings"
	"testing"
)

func TestLegacyQUICALPNRoundTrip(t *testing.T) {
	for _, uri := range []string{"hy2://secret@example.net:443", "tuic://11111111-1111-4111-8111-111111111111:secret@example.net:443"} {
		node, err := Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		for _, raw := range []any{"custom", []string{"custom", "h3"}, []any{"custom", "h3"}} {
			node["alpn"] = raw
			before := maps.Clone(node)
			shared, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(shared)
			if err != nil {
				t.Fatal(err)
			}
			want, _ := ALPNValues(raw, true)
			if !reflect.DeepEqual(restored["alpn"], want) {
				t.Fatal("ALPN lost on sharing")
			}
			if !reflect.DeepEqual(node, before) {
				t.Fatal("sharing changed source")
			}
		}
		for _, raw := range []any{nil, true, 42, "", "custom,h3", "h3\n", strings.Repeat("x", 256), []any{"h3", 2}, []any{""}} {
			node["alpn"] = raw
			if _, err := Export(node); err == nil {
				t.Fatal("invalid ALPN silently exported")
			}
		}
		for _, q := range []string{"?alpn=h3,,custom", "?alpn=h3%0A", "?alpn=,h3"} {
			if _, err := Parse(uri + q); err == nil {
				t.Fatal("invalid URI ALPN accepted")
			}
		}
	}
}
