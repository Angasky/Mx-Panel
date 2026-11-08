package remote

import (
	"context"
	"encoding/json"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestSingOutboundUDPRestriction(t *testing.T) {
	for _, kind := range []string{"socks5", "ss", "vmess", "vless", "trojan", "hysteria2", "tuic"} {
		t.Run(kind, func(t *testing.T) {
			base := Record{"type": kind, "server": "node.example.net", "port": 443}
			switch kind {
			case "ss":
				base["password"], base["cipher"] = "fixture-secret", "aes-128-gcm"
			case "vmess", "vless":
				base["uuid"] = "11111111-1111-4111-8111-111111111111"
			case "tuic":
				base["uuid"] = "11111111-1111-4111-8111-111111111111"
				fallthrough
			case "trojan", "hysteria2":
				base["password"] = "fixture-secret"
			}
			if kind == "trojan" {
				base["tls"] = true
			}
			for _, setting := range []any{false, true, "false", nil, 0} {
				node := maps.Clone(base)
				node["udp"] = setting
				before := maps.Clone(node)
				out, err := singRelayOutbound(node, "proxy")
				if _, ok := setting.(bool); !ok {
					if err == nil {
						t.Fatal("invalid UDP flag accepted")
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if setting == false && out["network"] != "tcp" || setting == true && out["network"] != nil {
					t.Fatal("network restriction changed")
				}
				if binary := os.Getenv("MXIOC_TEST_SING_BOX"); binary != "" {
					raw, err := json.Marshal(Record{"outbounds": []any{out}})
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(t.TempDir(), "config.json")
					if err := os.WriteFile(file, raw, 0600); err != nil {
						t.Fatal(err)
					}
					ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
					output, err := exec.CommandContext(ctx, binary, "check", "-c", file).CombinedOutput()
					cancel()
					if err != nil {
						t.Fatal("native policy config rejected", err, string(output))
					}
				}
				if !reflect.DeepEqual(node, before) {
					t.Fatal("source modified")
				}
			}
			out, err := singRelayOutbound(base, "proxy")
			if err != nil || out["network"] != nil {
				t.Fatal("default restricted", err)
			}
			base["udp"] = false
			if _, err := NodeOutbound(base, "proxy"); err == nil {
				t.Fatal("Xray restriction lost")
			}
		})
	}
	node := Record{"type": "vless", "server": "node.example.net", "port": 443, "uuid": "11111111-1111-4111-8111-111111111111", "udp": false, "network": "ws", "ws-opts": Record{"path": "/relay"}}
	out, err := singRelayOutbound(node, "proxy")
	if err != nil || out["network"] != "tcp" || out["transport"].(Record)["type"] != "ws" {
		t.Fatal("transport confused with network restriction", err)
	}
	node["skip-cert-verify"] = true
	if _, err := singRelayOutbound(node, "proxy"); err == nil {
		t.Fatal("TLS guard bypassed")
	}
}
