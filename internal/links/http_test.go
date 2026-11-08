package links

import (
	"encoding/json"
	"net/url"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestPythonHTTPProxyOptionsRoundTrip(t *testing.T) {
	pin := strings.Repeat("AB", 32)
	query := url.Values{"sni": {"tls.example"}, "fingerprint": {pin}, "name-cert-verify": {"cert.example"}, "host": {"proxy.example"}, "user-agent": {"Custom Agent/1.0"}, "skip-cert-verify": {"false"}}
	uri := "https://u%2Bname:p%40ss%3Aword@[2001:db8::1]?" + query.Encode() + "#Legacy"
	node, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if node["port"] != 443 || node["username"] != "u+name" || node["password"] != "p@ss:word" || node["udp"] != false || node["sni"] != "tls.example" || node["name-cert-verify"] != "cert.example" || node["headers"].(map[string]any)["User-Agent"] != "Custom Agent/1.0" {
		t.Fatal("HTTP parameters lost", node)
	}
	shared, err := Export(node)
	if err != nil {
		t.Fatal(err)
	}
	restored, err := Parse(shared)
	if err != nil || !reflect.DeepEqual(node, restored) {
		t.Fatal("HTTP round trip changed settings", err, node, restored)
	}
	if node["client-fingerprint"] != nil {
		t.Fatal("certificate pin treated as client fingerprint")
	}
	for _, uri := range []string{"http://example.net", "http://example.net/", "https://example.net/", "http://user@example.net:8080?ua=Agent%20One&host=proxy.example"} {
		node, err := Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		out, err := Export(node)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := Parse(out)
		if err != nil || !reflect.DeepEqual(node, roundtrip) {
			t.Fatal("default port or credentials changed", uri, err)
		}
	}
}

func TestHTTPProxyRejectsAmbiguousOrLossyOptions(t *testing.T) {
	for _, uri := range []string{
		"https://example.net?tls=false", "https://example.net?fingerprint=chrome",
		"http://example.net?name-cert-verify=cert.example", "http://example.net?udp=true",
		"https://example.net?insecure=1&skip-cert-verify=false", "http://example.net?host=a&host=b",
		"http://example.net?ua=a&user-agent=b", "http://example.net?host=ok%0D%0AX-Injected%3Ayes",
		"https://example.net?name-cert-verify=ok%00bad", "http://example.net?type=ws",
		"http://example.net:", "http://example.net:0", "http://example.net:65536", "http://example.net/path",
	} {
		if _, err := Parse(uri); err == nil {
			t.Errorf("accepted invalid HTTP URI %s", uri)
		}
	}
	for _, extra := range []map[string]any{
		{"headers": map[string]any{"Authorization": "secret"}},
		{"headers": map[string]any{"Host": "a", "host": "b"}},
		{"headers": map[string]any{"Host": "a\r\nb"}},
		{"headers": map[string]any{"Host": 12}},
		{"sni": "a", "servername": "b", "tls": true},
		{"name-cert-verify": "a"}, {"udp": true}, {"tls": "true"}, {"client-fingerprint": "chrome"},
		{"ws-opts": map[string]any{"path": "/"}}, {"dialer-proxy": "upstream"},
	} {
		node := map[string]any{"type": "http", "server": "example.net", "port": 8080}
		for k, v := range extra {
			node[k] = v
		}
		if _, err := Export(node); err == nil {
			t.Errorf("export silently lost option: %#v", extra)
		}
	}
}

func TestHTTPYAMLHeadersAndSNI(t *testing.T) {
	node := map[string]any{"name": "test", "type": "http", "server": "example.net", "port": 443, "tls": true, "servername": "tls.example", "headers": map[string]any{"host": "proxy.example", "user-agent": "Agent One"}}
	uri, err := Export(node)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Parse(uri)
	if err != nil || got["sni"] != "tls.example" || got["headers"].(map[string]any)["Host"] != "proxy.example" {
		t.Fatal("YAML options lost", err)
	}
}

func TestPythonHTTPReferenceFixtures(t *testing.T) {
	raw, err := os.ReadFile("testdata/python_http.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Cases []struct {
			URI  string
			Node map[string]any
		}
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	for _, row := range fixture.Cases {
		node, err := Parse(row.URI)
		if err != nil {
			t.Fatal(err)
		}
		// JSON numbers are float64 in the recorded Python result.
		encoded, err := json.Marshal(node)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err = json.Unmarshal(encoded, &got); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(got, row.Node) {
			t.Fatalf("Python HTTP fixture mismatch: %#v != %#v", got, row.Node)
		}
	}
}
