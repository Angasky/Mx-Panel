package remote

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rawPanelFixture() Record {
	return Record{"port": 24001, "protocol": "vmess", "settings": Record{"clients": []any{Record{"id": "11111111-1111-4111-8111-111111111111", "email": "existing-user"}}, "disableInsecureEncryption": false}, "streamSettings": Record{"network": "tcp", "security": "none"}, "remark": "raw panel"}
}

func TestRawPanelConfigurationValidationAndPreservation(t *testing.T) {
	input := rawPanelFixture()
	input["id"], input["goCreateKey"] = 9, "forged-owner"
	input["sniffing"] = `{"enabled":true,"custom":{"nested":1}}`
	row, err := PrepareRawPanelInbound(input)
	if err != nil {
		t.Fatal(err)
	}
	if row["id"] != nil || row["goCreateKey"] != nil || row["enable"] != true {
		t.Fatal("unexpected fields", row)
	}
	row["settings"].(Record)["clients"].([]any)[0].(Record)["id"] = "changed"
	if input["settings"].(Record)["clients"].([]any)[0].(Record)["id"] == "changed" {
		t.Fatal("aliased input")
	}
	for _, raw := range []any{nil, "{}", []any{}, Record{}, Record{"port": true, "protocol": "vmess"}, Record{"port": 65536, "protocol": "vmess"}, Record{"port": 443, "protocol": "invalid"}, Record{"port": 443, "protocol": "vmess", "settings": "{} {}"}, Record{"port": 443, "protocol": "vmess", "settings": Record{"clients": []any{"bad"}}}, Record{"port": 443, "protocol": "vmess", "enable": "true"}, Record{"port": 443, "protocol": "vmess", "remark": strings.Repeat("x", 256<<10)}} {
		if _, err := PrepareRawPanelInbound(raw); err == nil {
			t.Fatalf("accepted invalid input type %T", raw)
		}
	}
}

func TestRawPanelCreateDisconnectRestartAndExplicitPortConflict(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	panel, rows, writes, mode := createPanelFixture(t)
	input := rawPanelFixture()
	desired, err := PrepareRawPanelInbound(input)
	if err != nil {
		t.Fatal(err)
	}
	entry := createEntry(t)
	entry["desired"] = desired
	entry["rawPanel"] = true
	payload := Record{"inbound": input}
	*rows = append(*rows, Record{"id": 3, "port": 24001})
	if _, err := createPanelInbound(context.Background(), panel, Record{}, payload, entry, func(Record) error { return nil }); err == nil || writes.Load() != 0 || desired["port"] != 24001 {
		t.Fatal("raw port collision silently changed port", err)
	}
	*rows = []Record{}
	mode.Store("disconnect")
	persist := func(e Record) error { return m.persistCreate("raw", e) }
	if _, err := createPanelInbound(context.Background(), panel, Record{}, payload, entry, persist); err == nil {
		t.Fatal("disconnect reported success")
	}
	wire, err := os.ReadFile(filepath.Join(m.root, "inbound-creates.json"))
	if err != nil || strings.Contains(string(wire), "11111111-1111") || strings.Contains(string(wire), "existing-user") {
		t.Fatal("credentials not sealed", err)
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := m.loadCreate("raw")
	if err != nil {
		t.Fatal(err)
	}
	saved["desired"], err = m.OpenUser(value(saved["sealedDesired"]))
	if err != nil {
		t.Fatal(err)
	}
	mode.Store("")
	result, err := createPanelInbound(context.Background(), panel, Record{}, payload, saved, persist)
	if err != nil || result["reused"] != true || writes.Load() != 1 {
		t.Fatal("replay or failed reconciliation", err, writes.Load())
	}
	actual, _ := inboundObject(result["inbound"].(Record)["settings"])
	expected, _ := json.Marshal(input["settings"])
	got, _ := json.Marshal(actual)
	if string(expected) != string(got) {
		t.Fatal("original credentials changed")
	}
	if _, err = createPanelInbound(context.Background(), panel, Record{}, payload, saved, persist); err != nil || writes.Load() != 1 {
		t.Fatal("confirmed retry replayed", err)
	}
	(*rows)[0]["settings"] = Record{"clients": []any{Record{"id": "replaced-credential"}}}
	if _, err = createPanelInbound(context.Background(), panel, Record{}, payload, saved, persist); err == nil || writes.Load() != 1 {
		t.Fatal("changed credentials reused as original creation", err)
	}
}

func TestRawPanelCreateRejectsStandaloneBeforeSSH(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		m, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		server := serverPayload()
		server["installType"] = kind
		delete(server, "panelAddress")
		saved, err := m.Save(server)
		if err != nil {
			t.Fatal(err)
		}
		_, err = m.CreateInbound(context.Background(), value(saved["id"]), "clash", Record{"operationId": strings.Repeat("a", 32), "inbound": rawPanelFixture()})
		if err == nil || !strings.Contains(err.Error(), "仅支持面板服务器") {
			t.Fatal("standalone raw request reached transport", err)
		}
	}
}
