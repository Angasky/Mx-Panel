package remote

import "testing"

func TestInboundMalformedAccountsNeverExportAsAnonymous(t *testing.T) {
	for _, protocol := range []string{"socks", "http"} {
		for _, accounts := range []any{"user:password", Record{"user": "alice", "pass": "secret"}, true, []any{nil}, []any{"{}"}, []any{Record{"user": "alice", "pass": "secret"}, nil}} {
			nodes, err := InboundNodes(Record{"protocol": protocol, "port": 1080, "settings": Record{"accounts": accounts}}, Record{"host": "example.com"})
			if err == nil || nodes != nil {
				t.Fatalf("%s malformed accounts exported: %#v %v", protocol, nodes, err)
			}
		}
		for _, accounts := range []any{nil, []any{}, []any{Record{}}} {
			nodes, err := InboundNodes(Record{"protocol": protocol, "port": 1080, "settings": Record{"accounts": accounts}}, Record{"host": "example.com"})
			if err != nil || len(nodes) != 1 {
				t.Fatalf("%s valid anonymous: %#v %v", protocol, nodes, err)
			}
		}
		nodes, err := InboundNodes(Record{"protocol": protocol, "port": 1080, "settings": Record{"accounts": []any{Record{"user": "alice", "pass": "secret"}}}}, Record{"host": "example.com"})
		if err != nil || len(nodes) != 1 || nodes[0]["username"] != "alice" || nodes[0]["password"] != "secret" {
			t.Fatalf("credentials lost: %#v %v", nodes, err)
		}
	}
}
