package links

import (
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRealityHybridPolicyAndShortIDRoundTrip(t *testing.T) {
	for _, flag := range []string{"true", "false"} {
		for _, sid := range []string{"", "null", "None", "75e4", "ABcd"} {
			uri := "vless://11111111-1111-4111-8111-111111111111@example.net:443?security=reality&pbk=key&sid=" + sid + "&support-x25519mlkem768=" + flag
			node, err := Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			shared, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			u, _ := url.Parse(shared)
			if u.Query().Get("support-x25519mlkem768") != flag {
				t.Fatal("hybrid policy lost")
			}
			restored, err := Parse(shared)
			if err != nil || !reflect.DeepEqual(node, restored) {
				t.Fatal("Reality changed on sharing", err)
			}
		}
	}
	for _, query := range []string{"security=reality&pbk=key&sid=abc", "security=reality&pbk=key&sid=invalid", "security=tls&support-x25519mlkem768=true", "security=reality&pbk=key&support-x25519mlkem768=yes", "security=reality&pbk=key&support-x25519mlkem768=true&support-x25519mlkem768=false"} {
		if _, err := Parse("vless://id@example.net:443?" + query); err == nil {
			t.Fatal("invalid Reality policy accepted")
		}
	}
	for _, raw := range []any{true, map[string]any{"public-key": "key", "short-id": 12}, map[string]any{"public-key": "key", "support-x25519mlkem768": "false"}, map[string]any{"public-key": "key", "unknown": "secret"}, map[string]any{"public-key": "key", "short-id": strings.Repeat("ab", 9)}} {
		if _, err := NormalizeReality(raw); err == nil {
			t.Fatal("malformed options accepted")
		}
	}
}
