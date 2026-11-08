package links

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"testing"
)

func TestPythonTUICCredentialsAndAliases(t *testing.T) {
	const id = "11111111-1111-4111-8111-111111111111"
	secret := "pass:@/+ 中文"
	for _, auth := range []string{id, id + ":", url.UserPassword(id, secret).String()} {
		uri := "tuic://" + auth + "@example.net:443?password=" + url.QueryEscape(secret) + "&congestion-controller=cubic&udp-relay-mode=quic"
		node, err := Parse(uri)
		if err != nil {
			t.Fatal("compatible TUIC rejected", err)
		}
		if node["uuid"] != id || node["password"] != secret || node["congestion-controller"] != "cubic" || node["udp-relay-mode"] != "quic" {
			t.Fatal("TUIC parameters lost")
		}
		shared, err := Export(node)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Parse(shared)
		if err != nil || restored["password"] != secret || restored["uuid"] != id {
			t.Fatal("TUIC credential roundtrip failed", err)
		}
	}
	for _, suffix := range []string{
		"?password=other", "?password=one&password=one", "?congestion_control=bbr&congestion-controller=cubic", "?udp_relay_mode=native&udp-relay-mode=quic",
	} {
		if _, err := Parse("tuic://" + id + ":secret@example.net:443" + suffix); err == nil {
			t.Fatal("ambiguous TUIC accepted")
		}
	}
	for _, uri := range []string{"tuic://" + id + "@example.net:443", "tuic://" + id + ":@example.net:443?password=", "trojan://secret@example.net:443?password=other"} {
		if _, err := Parse(uri); err == nil {
			t.Fatal("invalid credential source accepted")
		}
	}
}

func TestPythonVMessHostSNIFallback(t *testing.T) {
	for _, network := range []string{"tcp", "ws", "grpc"} {
		for _, sni := range []string{"", "tls.example.net"} {
			raw, _ := json.Marshal(map[string]any{"add": "example.net", "port": 443, "id": "11111111-1111-4111-8111-111111111111", "net": network, "tls": "tls", "host": "cdn.example.net", "sni": sni})
			node, err := Parse("vmess://" + base64.StdEncoding.EncodeToString(raw))
			if err != nil {
				t.Fatal(err)
			}
			expected := sni
			if expected == "" {
				expected = "cdn.example.net"
			}
			if node["servername"] != expected {
				t.Fatal("SNI fallback lost")
			}
			uri, err := Export(node)
			if err != nil {
				t.Fatal(err)
			}
			restored, err := Parse(uri)
			if err != nil || restored["servername"] != expected {
				t.Fatal("SNI roundtrip lost", err)
			}
		}
	}
}

func TestPythonHysteriaCredentials(t *testing.T) {
	for _, sample := range []struct{ auth, want string }{
		{"secret", "secret"}, {"account:secret", "secret"}, {"account:", "account"},
		{url.User("literal:colon@+/ 中文").String(), "literal:colon@+/ 中文"},
		{url.UserPassword("account", "literal:colon@+/ 中文").String(), "literal:colon@+/ 中文"},
	} {
		node, err := Parse("hy2://" + sample.auth + "@example.net:443")
		if err != nil || node["password"] != sample.want {
			t.Fatal("Python HY2 credential selection mismatch", err)
		}
		uri, err := Export(node)
		if err != nil {
			t.Fatal(err)
		}
		restored, err := Parse(uri)
		if err != nil || restored["password"] != sample.want {
			t.Fatal("HY2 credential roundtrip lost", err)
		}
	}
}
