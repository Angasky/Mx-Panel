package remote

import (
	"maps"
	"reflect"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestImportedHTTPOutbound(t *testing.T) {
	for _, uri := range []string{"http://user:pass%40word@example.net:8080#proxy", "https://user:pass%40word@example.net:443?sni=proxy.example.net#proxy"} {
		node, err := links.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		before := maps.Clone(node)
		for _, kind := range []string{"xray", "sing-box"} {
			convert := NodeOutbound
			if kind == "sing-box" {
				convert = singRelayOutbound
			}
			out, err := convert(node, "landing")
			if err != nil {
				t.Fatal(kind, err)
			}
			if kind == "sing-box" {
				if out["type"] != "http" || out["username"] != "user" || out["password"] != "pass@word" {
					t.Fatal("HTTP auth changed")
				}
				if node["tls"] == true && out["tls"].(Record)["server_name"] != "proxy.example.net" {
					t.Fatal("SNI lost")
				}
			} else {
				endpoint := out["settings"].(Record)["servers"].([]any)[0].(Record)
				auth := endpoint["users"].([]any)[0].(Record)
				if out["protocol"] != "http" || auth["user"] != "user" || auth["pass"] != "pass@word" {
					t.Fatal("HTTP auth changed")
				}
			}
			for _, patch := range []Record{{"udp": true}, {"skip-cert-verify": "true"}, {"headers": Record{"Host": "bad\r\nheader"}}, {"fingerprint": "unmapped-pin"}} {
				invalid := maps.Clone(node)
				maps.Copy(invalid, patch)
				if _, err := convert(invalid, "landing"); err == nil {
					t.Fatal("unsupported setting silently lost", kind)
				}
			}
		}
		if !reflect.DeepEqual(node, before) {
			t.Fatal("source node changed")
		}
	}
	// Keep the fail-closed behavior for protocols whose UDP capability would
	// otherwise be enabled despite an explicit restriction.
	node, _ := links.Parse("socks5://user:pass@example.net:1080?udp=false")
	if _, err := NodeOutbound(node, "landing"); err == nil {
		t.Fatal("SOCKS UDP restriction ignored")
	}
}
