package subsource

import (
	"reflect"
	"strings"
	"testing"
)

func TestLegacyQUICALPNSubscription(t *testing.T) {
	fixture := `proxies:
- name: legacy
  type: hysteria2
  server: node.example.net
  port: 443
  password: fixture-secret
  alpn: custom
`
	for _, alpn := range []string{"custom", "[custom, h3]"} {
		batch, err := Parse(strings.Replace(fixture, "alpn: custom", "alpn: "+alpn, 1))
		if err != nil || len(batch.Nodes) != 1 {
			t.Fatal("legacy scalar rejected", err)
		}
		want := []any{"custom"}
		if alpn != "custom" {
			want = append(want, "h3")
		}
		if !reflect.DeepEqual(batch.Nodes[0]["alpn"], want) {
			t.Fatal("ALPN not normalized for Mihomo")
		}
	}
	for _, alpn := range []string{"null", "42", "true", "[h3, 42]", `"custom,h3"`} {
		if _, err := Parse(strings.Replace(fixture, "alpn: custom", "alpn: "+alpn, 1)); err == nil {
			t.Fatal("invalid ALPN imported")
		}
	}
}
