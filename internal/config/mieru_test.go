package config

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func mieruNode() Document {
	return Document{"name": "Mieru", "type": "mieru", "server": "example.com", "port-range": "03000-03002", "username": "user", "password": "fixture-secret", "transport": "udp", "udp": true, "mtu": json.Number("1400"), "custom": Document{"keep": true}}
}

func TestMieruValidationNormalizationAndMirrorRollback(t *testing.T) {
	r, primary, mirror := fixture(t)
	n := mieruNode()
	if err := r.Mutate("clash", func(d Document) error { return EditNode(d, "POST", Document{"config": n}) }); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := r.Snapshot("clash")
	row := snapshot["nodes"].([]any)[0].(Document)
	saved := row["config"].(Document)
	if row["port"] != "3000-3002" || saved["transport"] != "UDP" || saved["mtu"] != nil || saved["custom"].(Document)["keep"] != true {
		t.Fatal("normalization or extensions lost", saved)
	}
	for _, change := range []Document{{"port": 2999}, {"port-range": "4000-3000"}, {"username": ""}, {"password": strings.Repeat("你", 22)}, {"transport": "QUIC"}, {"udp": "true"}, {"mtu": 1200}, {"multiplexing": "bad"}, {"handshake-mode": "bad"}, {"traffic-pattern": "Zg==\n"}} {
		copy := mieruNode()
		for k, v := range change {
			copy[k] = v
		}
		if err := ValidateNode(copy); err == nil {
			t.Fatal("invalid Mieru accepted", change)
		}
	}
	a, _ := os.ReadFile(primary)
	b, _ := os.ReadFile(mirror)
	if !bytes.Equal(a, b) {
		t.Fatal("mirror mismatch")
	}
	index, _ := r.index()
	record, _ := stateRecord(index, "clash")
	record["files"] = []any{primary, filepath.Join(r.Root, "absent", "mirror.yaml")}
	if err := r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	changed := mieruNode()
	changed["password"] = "changed"
	if err := r.Mutate("clash", func(d Document) error { return EditNode(d, "PUT", Document{"oldName": "Mieru", "config": changed}) }); err == nil {
		t.Fatal("mirror failure ignored")
	}
	after, _ := os.ReadFile(primary)
	if !bytes.Equal(a, after) {
		t.Fatal("failed write changed primary")
	}
}

func TestNativeGoMieruConfigWithRealMihomo(t *testing.T) {
	binary := os.Getenv("MXIOC_MIHOMO_BIN")
	if binary == "" {
		t.Skip("set MXIOC_MIHOMO_BIN for native Mieru config validation")
	}
	for _, transport := range []string{"TCP", "UDP"} {
		for _, ranged := range []bool{false, true} {
			n := mieruNode()
			delete(n, "custom")
			n["transport"] = transport
			if !ranged {
				delete(n, "port-range")
				n["port"] = 2999
			}
			n["handshake-mode"] = "HANDSHAKE_STANDARD"
			n["traffic-pattern"] = "CCoQARoECAEQCiIYCAMQASoIMDAwMTAyMDMqCDA0MDUwNjA3"
			if err := ValidateNode(n); err != nil {
				t.Fatal(err)
			}
			raw, err := yaml.Marshal(Document{"mixed-port": 0, "mode": "rule", "proxies": []any{n}, "rules": []any{"MATCH,Mieru"}})
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			file := filepath.Join(root, "config.yaml")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			command := exec.CommandContext(ctx, binary, "-t", "-d", root, "-f", file)
			output, err := command.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatal("Mihomo rejected Go-generated Mieru", transport, ranged, err, string(output))
			}
		}
	}
}
