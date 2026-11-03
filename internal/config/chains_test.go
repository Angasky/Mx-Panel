package config

import (
	"os"
	"testing"
)

func TestChainCreateRenameMembershipAndInvalidRollback(t *testing.T) {
	r, primary, _ := fixture(t)
	err := r.Mutate("clash", func(doc Document) error {
		doc["proxies"] = []any{node("entry"), node("exit")}
		doc["proxies"].([]any)[1].(Document)["extension"] = Document{"preserve": true}
		doc["proxy-groups"] = []any{Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}}, Document{"name": "Media", "type": "select", "proxies": []any{"DIRECT"}}}
		doc["rules"] = []any{"MATCH,Proxy"}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	change := func(method string, payload Document) error {
		return r.Mutate("clash", func(doc Document) error { return EditChain(doc, method, payload, []string{"Proxy", "Media"}) })
	}
	if err = change("POST", Document{"name": "chain", "entry": "entry", "exit": "exit", "groups": []any{"Proxy"}}); err != nil {
		t.Fatal(err)
	}
	snap, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	nodes := snap["nodes"].([]any)
	chain := nodes[2].(Document)["config"].(Document)
	if chain["dialer-proxy"] != "entry" || chain["extension"].(Document)["preserve"] != true {
		t.Fatal("landing options lost")
	}
	if err = r.Mutate("clash", func(doc Document) error { doc["rules"] = []any{"DOMAIN,example.com,chain", "MATCH,Proxy"}; return nil }); err != nil {
		t.Fatal(err)
	}
	if err = change("PUT", Document{"oldName": "chain", "name": "renamed", "entry": "entry", "exit": "exit", "groups": []any{"Media"}}); err != nil {
		t.Fatal(err)
	}
	snap, _ = r.Snapshot("clash")
	if snap["rules"].([]any)[0].(Document)["action"] != "renamed" {
		t.Fatal("rename lost rule reference")
	}
	before, _ := os.ReadFile(primary)
	for _, payload := range []Document{
		{"name": "cycle", "entry": "renamed", "exit": "exit"},
		{"name": "bad", "entry": "entry", "exit": "entry"},
		{"name": "bad", "entry": "entry", "exit": "exit", "groups": []any{"missing"}},
		{"name": "server", "entry": "entry", "exit": "exit", "mode": "server"},
	} {
		if err = change("POST", payload); err == nil {
			t.Fatal("invalid chain accepted", payload)
		}
	}
	after, _ := os.ReadFile(primary)
	if string(before) != string(after) {
		t.Fatal("invalid chain modified persisted configuration")
	}
	if err = r.Mutate("clash", func(doc Document) error { return EditNode(doc, "DELETE", Document{"name": "entry"}) }); err == nil {
		t.Fatal("deleted active chain entry")
	}
}
