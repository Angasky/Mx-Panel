package config

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

func TestSnellEditingUsesCompleteValidation(t *testing.T) {
	n := Document{"name": "Snell", "type": "snell", "server": "example.com", "port": 443, "psk": "secret", "version": json.Number("5"), "obfs-opts": Document{"mode": "shadow-tls", "host": "EXAMPLE.COM.", "password": "secret", "version": json.Number("3"), "alpn": []any{"h2"}}}
	if err := ValidateNode(n); err != nil {
		t.Fatal(err)
	}
	if n["obfs-opts"].(map[string]any)["host"] != "example.com" {
		t.Fatal("host not normalized")
	}
	n["obfs-opts"].(map[string]any)["alpn"] = []any{"h3"}
	if err := ValidateNode(n); err == nil {
		t.Fatal("edit accepted invalid ShadowTLS")
	}
}

func TestNativeGoSnellConfigWithRealMihomo(t *testing.T) {
	binary := os.Getenv("MXIOC_MIHOMO_BIN")
	if binary == "" {
		t.Skip("set MXIOC_MIHOMO_BIN for native Snell config validation")
	}
	for _, mode := range []string{"none", "http", "tls", "shadow-tls", "restls", "jls"} {
		t.Run(mode, func(t *testing.T) {
			n := Document{"name": "Snell", "type": "snell", "server": "127.0.0.1", "port": 443, "psk": "test-password", "version": 5, "udp": true, "reuse": true}
			obfs := Document{"mode": mode, "host": "example.com"}
			switch mode {
			case "shadow-tls":
				obfs["password"] = "secret"
				obfs["version"] = 3
				obfs["alpn"] = []any{"h2", "http/1.1"}
			case "restls":
				obfs["password"] = "secret"
				obfs["version-hint"] = "tls13"
			case "jls":
				obfs["password"] = "secret"
				obfs["username"] = "user"
			}
			if mode != "none" {
				n["obfs-opts"] = obfs
			}
			if err := ValidateNode(n); err != nil {
				t.Fatal(err)
			}
			raw, err := yaml.Marshal(Document{"mixed-port": 0, "mode": "rule", "proxies": []any{n}, "rules": []any{"MATCH,Snell"}})
			if err != nil {
				t.Fatal(err)
			}
			root := t.TempDir()
			file := filepath.Join(root, "config.yaml")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			output, err := exec.CommandContext(ctx, binary, "-t", "-d", root, "-f", file).CombinedOutput()
			if err != nil {
				t.Fatal("Mihomo rejected Go Snell configuration", err, string(output))
			}
		})
	}
}
