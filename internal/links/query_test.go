package links

import (
	"encoding/base64"
	"net/url"
	"reflect"
	"testing"
)

func TestLegacyPythonQueryAliasesRoundTrip(t *testing.T) {
	for _, tc := range []struct{ scheme, canonical, aliases string }{
		{"vless", "security=reality&type=grpc&sni=tls.example&fp=chrome&pbk=key&sid=abcd&serviceName=vpn", "security=reality&network=grpc&peer=tls.example&fingerprint=chrome&publicKey=key&shortId=abcd&service_name=vpn"},
		{"trojan", "type=ws&sni=tls.example&fp=chrome&path=%2Fvpn&host=cdn.example", "network=ws&servername=tls.example&fingerprint=chrome&path=%2Fvpn&host=cdn.example"},
		{"hysteria2", "sni=tls.example&obfs=salamander&obfs-password=a%2Bb%26c&upmbps=20&downmbps=50", "peer=tls.example&obfs=salamander&obfsPassword=a%2Bb%26c&up=20&down=50"},
		{"tuic", "sni=tls.example", "servername=tls.example"},
		{"socks5", "sni=tls.example&tls=true", "servername=tls.example&tls=true"},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			prefix := tc.scheme + "://11111111-1111-4111-8111-111111111111:password@example.net:443?"
			want, err := Parse(prefix + tc.canonical)
			if err != nil {
				t.Fatal(err)
			}
			got, err := Parse(prefix + tc.aliases)
			if err != nil || !reflect.DeepEqual(got, want) {
				t.Fatalf("alias mismatch: %v", err)
			}
			shared, err := Export(got)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(shared)
			if err != nil || !reflect.DeepEqual(got, restored) {
				t.Fatalf("round trip changed settings: %v\n%#v\n%#v", err, got, restored)
			}
		})
	}
}

func TestLegacyQueryAliasesRejectAmbiguity(t *testing.T) {
	for _, query := range []string{
		"type=ws&network=grpc", "sni=a&peer=b", "peer=a&servername=b",
		"peer=a&peer=a", "sni=a&sni=a&peer=a", "pbk=a&publicKey=b",
		"sid=ab&shortId=cd", "fp=chrome&fingerprint=firefox",
		"serviceName=a&service_name=b", "network=xhttp&security=tls&service_name=vpn",
	} {
		if _, err := Parse("vless://id@example.net:443?" + query); err == nil {
			t.Errorf("accepted ambiguous or incompatible query %s", query)
		}
	}
	for _, scheme := range []string{"http", "https", "socks5", "hysteria2", "tuic"} {
		if _, err := Parse(scheme + "://id:password@example.net:443?fingerprint=chrome"); err == nil {
			t.Errorf("client fingerprint alias accepted for %s", scheme)
		}
	}
	q := url.Values{"sni": {"same"}, "peer": {"same"}, "servername": {"same"}}
	if err := normalizeQueryAliases(q, "vless"); err != nil || len(q) != 1 || q.Get("sni") != "same" {
		t.Fatal("identical aliases rejected", err)
	}
}

func TestPythonTransportDefaults(t *testing.T) {
	for _, scheme := range []string{"vless", "trojan", "vmess"} {
		for _, network := range []string{"ws", "grpc"} {
			uri := scheme + "://id@example.net:443?network=" + network
			if scheme == "vmess" {
				uri = "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"add":"example.net","port":443,"id":"id","net":"`+network+`"}`))
			}
			node, err := Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			key, want := "path", "/"
			if network == "grpc" {
				key, want = "grpc-service-name", "grpc"
			}
			if node[network+"-opts"].(map[string]any)[key] != want {
				t.Fatalf("%s %s default lost", scheme, network)
			}
		}
	}
}
