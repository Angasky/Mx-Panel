package links

import (
	"reflect"
	"strings"
	"testing"
)

func TestSnellAdvancedObfuscationValidationAndLosslessExport(t *testing.T) {
	for _, obfs := range []map[string]any{
		{"mode": "http", "host": " CDN.Example.COM. "},
		{"mode": "tls", "host": "例子.测试"},
		{"mode": "shadow-tls", "host": "cdn.example.com", "password": "secret", "version": 3, "alpn": []any{"h2", "http/1.1"}},
		{"mode": "restls", "host": "cdn.example.com", "password": "secret", "version-hint": "tls13"},
		{"mode": "jls", "host": "cdn.example.com", "password": "secret", "username": "user"},
	} {
		node := map[string]any{"name": "Snell", "type": "snell", "server": "example.com", "port": 443, "psk": "secret", "version": 5, "udp": true, "reuse": true, "obfs-opts": obfs}
		beforeHost := obfs["host"]
		normalized, err := NormalizeSnell(node)
		if err != nil {
			t.Fatal(obfs["mode"], err)
		}
		if obfs["host"] != beforeHost {
			t.Fatal("input mutated")
		}
		mode := obfs["mode"].(string)
		uri, err := Export(normalized)
		if mode == "http" || mode == "tls" {
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := Parse(uri)
			if err != nil || !reflect.DeepEqual(parsed, normalized) {
				t.Fatal("roundtrip", parsed, normalized, err)
			}
		} else if err == nil {
			t.Fatal("advanced obfuscation lost", uri)
		}
	}
}

func TestSnellMalformedOptionsAndUnknownExportFields(t *testing.T) {
	base := func() map[string]any {
		return map[string]any{"name": "n", "type": "snell", "server": "example.com", "port": 443, "psk": "secret", "version": 5}
	}
	for _, change := range []map[string]any{
		{"psk": strings.Repeat("你", 342)}, {"psk": "\xff"}, {"version": nil}, {"version": true},
		{"udp": "true"}, {"tfo": 1}, {"reuse": nil}, {"obfs-opts": false},
		{"obfs-opts": map[string]any{"mode": "http", "host": "localhost"}},
		{"obfs-opts": map[string]any{"mode": "tls", "host": "a..example.com"}},
		{"obfs-opts": map[string]any{"mode": "jls", "host": "example.com", "password": "p"}},
		{"obfs-opts": map[string]any{"mode": "restls", "host": "example.com", "password": "p", "version-hint": "auto"}},
		{"obfs-opts": map[string]any{"mode": "shadow-tls", "host": "example.com", "password": "p", "version": 3, "alpn": "h2"}},
		{"obfs-opts": map[string]any{"mode": "shadow-tls", "host": "example.com", "password": "p", "version": 3, "alpn": []any{"h3"}}},
	} {
		n := base()
		for k, v := range change {
			n[k] = v
		}
		if _, err := NormalizeSnell(n); err == nil {
			t.Fatal("invalid options accepted", change)
		}
		if _, err := Export(n); err == nil {
			t.Fatal("invalid options exported", change)
		}
	}
	for _, change := range []map[string]any{
		{"custom-option": true}, {"obfs-opts": map[string]any{"mode": "http", "custom-option": "kept"}},
	} {
		n := base()
		for k, v := range change {
			n[k] = v
		}
		if _, err := NormalizeSnell(n); err != nil {
			t.Fatal("YAML extension lost", err)
		}
		if _, err := Export(n); err == nil {
			t.Fatal("lossy URI exported")
		}
	}
	n := base()
	n["obfs-opts"] = map[string]any{}
	normalized, err := NormalizeSnell(n)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := normalized["obfs-opts"]; ok {
		t.Fatal("empty obfs not removed")
	}
	if _, ok := n["obfs-opts"]; !ok {
		t.Fatal("input changed")
	}
}
