package remote

import (
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"strings"
	"testing"
)

func TestManagedALPNEditRoundTripAndGuards(t *testing.T) {
	old := transportEditFixture(t)
	before, _ := json.Marshal(old)
	for _, input := range []string{"http/1.1,h2", "http/1.1", "h2", ""} {
		row, err := prepareManagedCoreEdit(old, Record{"alpn": input})
		if err != nil {
			t.Fatal(err)
		}
		if managedCoreFields(row)["alpn"] != input {
			t.Fatal("editor lost ALPN order")
		}
		nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
		if err != nil {
			t.Fatal(err)
		}
		uri, err := links.Export(nodes[0])
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := links.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Join(anyStrings(parsed["alpn"]), ",") != input {
			t.Fatal("configured ALPN lost from subscription")
		}
		if !sameCoreInbound(Record{"alpn": parsed["alpn"]}, Record{"alpn": nodes[0]["alpn"]}) {
			t.Fatal("sharing changed ALPN")
		}
		if !sameCoreInbound(row["settings"].(Record), old["settings"].(Record)) {
			t.Fatal("credentials changed")
		}
		tls := row["streamSettings"].(Record)["tlsSettings"].(Record)
		original := old["streamSettings"].(Record)["tlsSettings"].(Record)
		if !sameCoreInbound(Record{"certificates": tls["certificates"]}, Record{"certificates": original["certificates"]}) {
			t.Fatal("certificate changed")
		}
	}
	after, _ := json.Marshal(old)
	if string(before) != string(after) {
		t.Fatal("source mutated")
	}
	for _, input := range []any{true, "h3", "h2,h2", "h2,", "h2\r\n"} {
		if _, err := prepareManagedCoreEdit(old, Record{"alpn": input}); err == nil {
			t.Fatal("invalid ALPN accepted")
		}
	}
	for _, input := range []string{"", "http/1.1", "http/1.1,h2"} {
		if _, err := prepareManagedCoreEdit(old, Record{"network": "grpc", "alpn": input}); err == nil {
			t.Fatal("invalid gRPC ALPN accepted")
		}
	}
	if _, err := prepareManagedCoreEdit(old, Record{"network": "grpc", "alpn": "h2"}); err != nil {
		t.Fatal(err)
	}
	delete(old, "goCreateKey")
	if _, err := prepareManagedCoreEdit(old, Record{"alpn": "h2"}); err == nil {
		t.Fatal("legacy TLS edit exposed")
	}
}

func TestManagedALPNRejectsUnsupportedMetadata(t *testing.T) {
	for _, change := range []func(Record){
		func(r Record) { r["streamSettings"].(Record)["security"] = "reality" },
		func(r Record) { r["protocol"] = "hysteria" },
		func(r Record) { r["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"] = []any{"custom"} },
		func(r Record) { r["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"] = "h2" },
	} {
		row := transportEditFixture(t)
		change(row)
		if _, exists := managedCoreFields(row)["alpn"]; exists {
			t.Fatal("unsupported ALPN edit exposed")
		}
		if _, err := prepareManagedCoreEdit(row, Record{"alpn": "h2"}); err == nil {
			t.Fatal("unsupported metadata replaced")
		}
	}
	row := transportEditFixture(t)
	row["streamSettings"].(Record)["network"] = "xhttp"
	row["streamSettings"].(Record)["xhttpSettings"] = Record{"path": "/", "mode": "auto"}
	for _, value := range []string{"", "http/1.1"} {
		if _, err := prepareManagedCoreEdit(row, Record{"alpn": value}); err == nil {
			t.Fatal("XHTTP without h2 accepted")
		}
	}
	if _, err := prepareManagedCoreEdit(row, Record{"alpn": "h2"}); err != nil {
		t.Fatal(err)
	}
}

func TestTemplateALPNDefaultsOverridesAndRejection(t *testing.T) {
	for _, template := range []string{"vless-tcp-tls", "vmess-tcp-tls", "trojan-tls", "vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls", "vless-grpc-tls", "vmess-grpc-tls", "trojan-grpc-tls", "vless-xhttp-tls"} {
		t.Run(template, func(t *testing.T) {
			payload := Record{"template": template, "serverName": "node.example.com", "port": 24001, "certFile": "/fixture/cert", "keyFile": "/fixture/key"}
			baseline, err := buildInboundTemplate(payload, "")
			if err != nil {
				t.Fatal(err)
			}
			expected := []any{"h2", "http/1.1"}
			if grpcTemplate(template) || template == "vless-xhttp-tls" {
				expected = []any{"h2"}
			}
			if !sameCoreInbound(Record{"alpn": baseline["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"]}, Record{"alpn": expected}) {
				t.Fatal("default changed")
			}
			chosen := "http/1.1,h2"
			if grpcTemplate(template) {
				chosen = "h2"
			}
			payload["alpn"] = chosen
			row, err := buildInboundTemplate(payload, "")
			if err != nil {
				t.Fatal(err)
			}
			row["goCreateKey"] = "fixture"
			if managedCoreFields(row)["alpn"] != chosen {
				t.Fatal("creation/edit disagree")
			}
			for _, bad := range []any{true, []any{"h2"}, "h3", "h2,h2", "h2,", "h2\r\n"} {
				payload["alpn"] = bad
				if _, err := buildInboundTemplate(payload, ""); err == nil {
					t.Fatal("invalid ALPN accepted")
				}
			}
			payload["alpn"] = ""
			_, err = buildInboundTemplate(payload, "")
			needsH2 := grpcTemplate(template) || template == "vless-xhttp-tls"
			if (err != nil) != needsH2 {
				t.Fatal("wrong empty ALPN handling", err)
			}
		})
	}
	for _, template := range []string{"hysteria2", "tuic", "vmess-tcp", "vless-reality"} {
		if _, err := buildInboundTemplate(Record{"template": template, "serverName": "node.example.com", "certFile": "/fixture/cert", "keyFile": "/fixture/key", "alpn": "h2"}, "1.1.1.1"); err == nil {
			t.Fatal("unsupported protocol accepted ALPN override")
		}
	}
}
