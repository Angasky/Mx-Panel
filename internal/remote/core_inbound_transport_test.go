package remote

import (
	"encoding/json"
	"testing"
)

func transportEditFixture(t *testing.T) Record {
	t.Helper()
	row, err := buildInboundTemplate(Record{"template": "vless-tcp-tls", "port": 24001,
		"serverName": "node.example.com", "certFile": "/fixture/cert", "keyFile": "/fixture/key"}, "")
	if err != nil {
		t.Fatal(err)
	}
	row["goCreateKey"] = "fixture"
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	row["settings"].(Record)["clients"] = []any{user}
	return row
}

func TestManagedTransportSwitchPreservesCredentialsAndInput(t *testing.T) {
	for _, patch := range []Record{{"network": "ws", "wsPath": "/new-path"}, {"network": "grpc", "grpcService": "new-service"}, {"network": "tcp"}} {
		old := transportEditFixture(t)
		before, _ := json.Marshal(old)
		next, err := prepareManagedCoreEdit(old, patch)
		if err != nil {
			t.Fatal(err)
		}
		stream := next["streamSettings"].(Record)
		if stream["network"] != patch["network"] || next["protocol"] != old["protocol"] || !sameCoreInbound(next["settings"].(Record), old["settings"].(Record)) {
			t.Fatal("switch changed protocol or credentials")
		}
		oldTLS := old["streamSettings"].(Record)["tlsSettings"].(Record)
		newTLS := stream["tlsSettings"].(Record)
		if !sameCoreInbound(Record{"certificates": oldTLS["certificates"]}, Record{"certificates": newTLS["certificates"]}) || newTLS["serverName"] != oldTLS["serverName"] {
			t.Fatal("switch changed certificate material or SNI")
		}
		after, _ := json.Marshal(old)
		if string(before) != string(after) {
			t.Fatal("candidate preparation mutated the live source")
		}
	}
}

func TestManagedTransportSwitchRejectsLossyOrUnownedSources(t *testing.T) {
	for name, change := range map[string]func(Record){
		"legacy":         func(row Record) { delete(row, "goCreateKey") },
		"vision":         func(row Record) { anyRecords(row["settings"].(Record)["clients"])[0]["flow"] = "xtls-rprx-vision" },
		"reality":        func(row Record) { row["streamSettings"].(Record)["security"] = "reality" },
		"custom-alpn":    func(row Record) { row["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"] = []any{"custom"} },
		"socket-options": func(row Record) { row["streamSettings"].(Record)["sockopt"] = Record{"mark": 1} },
		"malformed-tcp":  func(row Record) { row["streamSettings"].(Record)["tcpSettings"] = true },
		"ws-headers": func(row Record) {
			stream := row["streamSettings"].(Record)
			stream["network"], stream["wsSettings"] = "ws", Record{"path": "/", "headers": Record{"Host": "custom.example.com"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			row := transportEditFixture(t)
			change(row)
			if _, exposed := managedCoreFields(row)["network"]; exposed {
				t.Fatal("lossy transport switch exposed in editor")
			}
			if _, err := prepareManagedCoreEdit(row, Record{"network": "grpc", "grpcService": "new"}); err == nil {
				t.Fatal("lossy or unowned transport switch accepted")
			}
		})
	}
	for _, patch := range []Record{{"network": "xhttp"}, {"network": true}, {"network": Record{}},
		{"network": "ws", "grpcService": "stale"}, {"network": "grpc", "wsPath": "/stale"}} {
		if _, err := prepareManagedCoreEdit(transportEditFixture(t), patch); err == nil {
			t.Fatal("unsupported or conflicting transport fields accepted")
		}
	}
}
