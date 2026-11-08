package remote

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestPanelShadowsocksTemplateAndDurableRetry(t *testing.T) {
	payload := Record{"template": "shadowsocks", "port": 24001, "remark": "dedicated SS"}
	desired, err := buildPanelShadowsocks(payload)
	if err != nil {
		t.Fatal(err)
	}
	settings := desired["settings"].(Record)
	secret := value(settings["password"])
	decoded, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(decoded) != 24 || settings["method"] != "aes-128-gcm" || settings["network"] != "tcp,udp" || settings["clients"] != nil {
		t.Fatal("not Python single-password SS model")
	}
	nodes, err := InboundNodes(desired, Record{"host": "example.net"})
	if err != nil || len(nodes) != 1 {
		t.Fatal(err)
	}
	uri, err := links.Export(nodes[0])
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := links.Parse(uri)
	if err != nil || parsed["password"] != secret || parsed["cipher"] != "aes-128-gcm" {
		t.Fatal("share lost authentication", err)
	}
	second, err := buildPanelShadowsocks(payload)
	if err != nil || second["settings"].(Record)["password"] == secret {
		t.Fatal("password reused")
	}
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	panel, _, writes, mode := createPanelFixture(t)
	mode.Store("disconnect")
	entry := createEntry(t)
	entry["desired"], entry["rawPanel"] = desired, true
	persist := func(e Record) error { return m.persistCreate("ss", e) }
	if _, err := createPanelInbound(context.Background(), panel, Record{}, payload, entry, persist); err == nil {
		t.Fatal("disconnect reported success")
	}
	wire, err := os.ReadFile(filepath.Join(m.root, "inbound-creates.json"))
	if err != nil || strings.Contains(string(wire), secret) {
		t.Fatal("password not sealed", err)
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := m.loadCreate("ss")
	if err != nil {
		t.Fatal(err)
	}
	saved["desired"], err = m.OpenUser(value(saved["sealedDesired"]))
	if err != nil {
		t.Fatal(err)
	}
	mode.Store("")
	result, err := createPanelInbound(context.Background(), panel, Record{}, payload, saved, persist)
	if err != nil || writes.Load() != 1 || result["reused"] != true {
		t.Fatal("retry replayed", err)
	}
	got, _ := inboundObject(result["inbound"].(Record)["settings"])
	if got["password"] != secret {
		t.Fatal("retry regenerated password")
	}
}

func TestPanelShadowsocksValidation(t *testing.T) {
	for _, payload := range []Record{{"template": "shadowsocks", "port": true}, {"template": "shadowsocks", "port": -1}, {"template": "shadowsocks", "port": 65536}, {"template": "shadowsocks", "remark": strings.Repeat("a", 101)}, {"template": "shadowsocks", "inbound": Record{}}, {"template": "other"}} {
		if err := ValidatePanelShadowsocks(payload); err == nil {
			t.Fatal("invalid template accepted")
		}
	}
	row, err := buildPanelShadowsocks(Record{"template": "shadowsocks"})
	if err != nil || row["port"].(int) < 20001 || row["port"].(int) > 65535 {
		t.Fatal("default port", err)
	}
}
