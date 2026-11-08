package remote

import (
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSingOutboundNormalizesLegacyPortWithoutChangingSource(t *testing.T) {
	for _, kind := range []string{"http", "socks5", "ss", "vmess", "vless", "trojan", "hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			for _, port := range []any{"443", json.Number("443"), 443} {
				node := Record{"type": kind, "server": "example.net", "port": port}
				switch kind {
				case "ss":
					node["password"], node["cipher"] = "fixture-secret", "aes-128-gcm"
				case "vmess", "vless":
					node["uuid"] = "11111111-1111-4111-8111-111111111111"
				case "tuic":
					node["uuid"] = "11111111-1111-4111-8111-111111111111"
					fallthrough
				case "trojan", "hysteria2":
					node["password"] = "fixture-secret"
				}
				before := maps.Clone(node)
				out, err := singRelayOutbound(node, "proxy")
				if err != nil || out["server_port"] != 443 {
					t.Fatal("native port must be an integer", out, err)
				}
				if !reflect.DeepEqual(node, before) {
					t.Fatal("source mutated")
				}
				if binary := os.Getenv("MXIOC_TEST_SING_BOX"); binary != "" {
					raw, _ := json.Marshal(Record{"outbounds": []any{out}})
					file := filepath.Join(t.TempDir(), "config.json")
					if err = os.WriteFile(file, raw, 0600); err != nil {
						t.Fatal(err)
					}
					if output, err := exec.Command(binary, "check", "-c", file).CombinedOutput(); err != nil {
						t.Fatal(string(output), err)
					}
				}
				for _, invalid := range []any{"443.5", 0, 65536, nil, true} {
					node["port"] = invalid
					if _, err = singRelayOutbound(node, "proxy"); err == nil {
						t.Fatal("invalid port accepted", invalid)
					}
				}
			}
		})
	}
}
