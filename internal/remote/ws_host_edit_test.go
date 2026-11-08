package remote

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestManagedWSHostEditPreservesHeadersAndSource(t *testing.T) {
	row, err := prepareManagedCoreEdit(transportEditFixture(t), Record{"network": "ws", "wsPath": "/owned"})
	if err != nil {
		t.Fatal(err)
	}
	ws := row["streamSettings"].(Record)["wsSettings"].(Record)
	ws["headers"] = Record{"host": "old.example.com", "X-Custom": "preserved"}
	before, _ := json.Marshal(row)
	for _, host := range []string{"cdn.example.com", ""} {
		next, err := prepareManagedCoreEdit(row, Record{"wsHost": host, "wsPath": "/edited"})
		if err != nil {
			t.Fatal(err)
		}
		headers := next["streamSettings"].(Record)["wsSettings"].(Record)["headers"].(Record)
		if headers["X-Custom"] != "preserved" || value(headers["Host"]) != host || headers["host"] != nil {
			t.Fatal("header edit lost or duplicated values")
		}
		if managedCoreFields(next)["wsHost"] != host {
			t.Fatal("editor lost host")
		}
		if !sameCoreInbound(next["settings"].(Record), row["settings"].(Record)) {
			t.Fatal("credentials changed")
		}
		after, _ := json.Marshal(row)
		if string(before) != string(after) {
			t.Fatal("source was mutated")
		}
	}
	for _, host := range []any{true, "bad host", "bad/path", "bad@host", "bad?query", "a\r\nb", strings.Repeat("a", 257)} {
		if _, err := prepareManagedCoreEdit(row, Record{"wsHost": host}); err == nil {
			t.Fatal("invalid host accepted")
		}
	}
	for _, options := range []Record{
		{"path": "/", "host": "native.example.com"},
		{"path": "/", "headers": true},
		{"path": "/", "headers": Record{"Host": "a", "host": "b"}},
		{"path": "/", "headers": Record{"Host": []any{"a"}}},
	} {
		row["streamSettings"].(Record)["wsSettings"] = options
		if _, exists := managedCoreFields(row)["wsHost"]; exists {
			t.Fatal("ambiguous host exposed")
		}
		if _, err := prepareManagedCoreEdit(row, Record{"wsHost": "new.example.com"}); err == nil {
			t.Fatal("ambiguous host overwritten")
		}
	}
}

func TestManagedWSHostSwitchAndSharing(t *testing.T) {
	row, err := prepareManagedCoreEdit(transportEditFixture(t), Record{"network": "ws", "wsPath": "/owned", "wsHost": "cdn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
	if err != nil || len(nodes) != 1 {
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
	if parsed["ws-opts"].(Record)["headers"].(Record)["Host"] != "cdn.example.com" {
		t.Fatal("share lost host")
	}
	if _, err := prepareManagedCoreEdit(row, Record{"network": "grpc"}); err == nil {
		t.Fatal("switch silently discarded Host")
	}
	row, err = prepareManagedCoreEdit(row, Record{"wsHost": ""})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := prepareManagedCoreEdit(row, Record{"network": "grpc"}); err != nil {
		t.Fatal("cleared Host still blocks switch", err)
	}
	for _, network := range []string{"tcp", "grpc"} {
		if _, err := prepareManagedCoreEdit(transportEditFixture(t), Record{"network": network, "wsHost": "stale"}); err == nil {
			t.Fatal("accepted stale WS host")
		}
	}
}

func TestTransportHostCreationValidationAndIdentity(t *testing.T) {
	for _, template := range []string{"vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls", "vless-xhttp-tls"} {
		t.Run(template, func(t *testing.T) {
			field := "wsHost"
			if template == "vless-xhttp-tls" {
				field = "xhttpHost"
			}
			payload := Record{"operationId": strings.Repeat("a", 32), "template": template, "port": 24001, "serverName": "node.example.com", "certFile": "/fixture/cert", "keyFile": "/fixture/key", "path": "/vpn", field: "cdn.example.com"}
			row, err := buildInboundTemplate(payload, "")
			if err != nil {
				t.Fatal(err)
			}
			if managedCoreFields(row)[field] != "cdn.example.com" {
				t.Fatal("creation lost Host")
			}
			_, hash, err := createRequestIdentity("profile", payload)
			if err != nil {
				t.Fatal(err)
			}
			payload[field] = "other.example.com"
			_, changed, err := createRequestIdentity("profile", payload)
			if err != nil || hash == changed {
				t.Fatal("Host absent from retry identity", err)
			}
			for _, bad := range []any{true, 12, "bad host", "a/b", "a?b", "a#b", "a@b", "a\r\nb", strings.Repeat("a", 257)} {
				payload[field] = bad
				if _, err := buildInboundTemplate(payload, ""); err == nil {
					t.Fatal("invalid Host accepted", template)
				}
			}
			payload[field] = ""
			if _, err := buildInboundTemplate(payload, ""); err != nil {
				t.Fatal("empty optional Host rejected", err)
			}
			for _, bad := range []any{true, 12, "no-slash", "/has space", "/query?x=1", "/fragment#x"} {
				payload["path"] = bad
				if _, err := buildInboundTemplate(payload, ""); err == nil {
					t.Fatal("uneditable path accepted", template)
				}
			}
		})
	}
}
