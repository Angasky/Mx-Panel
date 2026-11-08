package remote

import (
	"maps"
	"reflect"
	"strings"
	"testing"
	"text/template"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestSingHTTPImportedHeadersPreservedAndIndependent(t *testing.T) {
	node, err := links.Parse("https://user:pass@example.net:443?host=proxy.example.net&ua=old-client")
	if err != nil {
		t.Fatal(err)
	}
	original := maps.Clone(node["headers"].(map[string]any))
	out, err := singRelayOutbound(node, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	headers := out["headers"].(Record)
	if !reflect.DeepEqual(headers, original) {
		t.Fatal("imported headers changed", headers)
	}
	headers["Host"] = "changed.example.net"
	if !reflect.DeepEqual(node["headers"], original) {
		t.Fatal("conversion mutated source")
	}
	if _, err = NodeOutbound(node, "proxy"); err == nil {
		t.Fatal("unimplemented Xray header mapping silently ignored")
	}
}

func TestSingHTTPRejectsMalformedOrConflictingHeaders(t *testing.T) {
	for _, raw := range []any{nil, "bad", Record{"Bad Name": "x"}, Record{"X-Test": "a\r\nb"}, Record{"X-Test": "a\x00b"}, Record{"Host": 123}, Record{"Host": "a", "host": "b"}, Record{"Proxy-Authorization": "secret"}, Record{"Content-Length": "10"}, Record{"Transfer-Encoding": "chunked"}, Record{"Connection": "close"}} {
		node := Record{"type": "http", "server": "example.net", "port": 8080, "headers": raw}
		if _, err := singRelayOutbound(node, "proxy"); err == nil {
			t.Fatal("invalid header accepted", raw)
		}
	}
	node := Record{"type": "socks5", "server": "example.net", "port": 1080, "headers": Record{"User-Agent": "test"}}
	if _, err := singRelayOutbound(node, "proxy"); err == nil {
		t.Fatal("HTTP headers accepted on SOCKS")
	}
}

func TestXrayHTTPLiteralHeaders(t *testing.T) {
	node := Record{"type": "http", "server": "example.net", "port": 8080, "headers": Record{"user-agent": "old-client", "X-Literal": "{{.Target}} \"quoted\" \\slash"}}
	original := maps.Clone(node["headers"].(Record))
	out, err := NodeOutbound(node, "proxy")
	if err != nil {
		t.Fatal(err)
	}
	headers := out["settings"].(Record)["headers"].(Record)
	for key, raw := range headers {
		tmpl, err := template.New(key).Parse(raw.(string))
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		if err = tmpl.Execute(&b, Record{"Target": "must-not-interpolate"}); err != nil {
			t.Fatal(err)
		}
		expected := original[key]
		if key == "User-Agent" {
			expected = original["user-agent"]
		}
		if b.String() != expected {
			t.Fatal("literal header changed", key, b.String())
		}
	}
	if !reflect.DeepEqual(node["headers"], original) {
		t.Fatal("source changed")
	}
	for _, raw := range []any{nil, Record{"Host": "override"}, Record{"Proxy-Authorization": "secret"}, Record{"X-Test": "bad\r\nvalue"}} {
		node["headers"] = raw
		if _, err = NodeOutbound(node, "proxy"); err == nil {
			t.Fatal("unsupported header accepted", raw)
		}
	}
}
