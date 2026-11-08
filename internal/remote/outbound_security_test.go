package remote

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestXrayPlaintextTransportPolicy(t *testing.T) {
	for _, kind := range []string{"vless", "trojan"} {
		for _, host := range []string{"198.51.100.1", "2001:db8::1", "edge.example.com", "100.64.0.1", "127.0.0.1", "10.0.0.1", "::1", "fe80::1", "fc00::1", "router", "edge.test", "HOME.ARPA."} {
			t.Run(kind+"/"+host, func(t *testing.T) {
				n := Record{"type": kind, "server": host, "port": 443, "tls": false, "uuid": "11111111-1111-4111-8111-111111111111", "password": "fixture"}
				_, err := NodeOutbound(n, "proxy")
				allowed := host == "127.0.0.1" || host == "10.0.0.1" || host == "::1" || host == "fe80::1" || host == "fc00::1" || host == "router" || host == "edge.test" || host == "HOME.ARPA."
				if xrayPrivateAddress(host) != allowed {
					t.Fatal("transport exception mismatch")
				}
				if (err == nil) != (allowed && validHost(host)) {
					t.Fatalf("allowed=%v, err=%v", allowed, err)
				}
				if _, err := singRelayOutbound(n, "proxy"); (err == nil) != validHost(host) {
					t.Fatal("Xray policy leaked into sing-box", err)
				}
				n["tls"] = true
				if _, err := NodeOutbound(n, "proxy"); (err == nil) != validHost(host) {
					t.Fatal("TLS rejected", err)
				}
			})
		}
	}
}

func TestXrayPlaintextPolicyWithRealCore(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary == "" {
		t.Skip("set MXIOC_TEST_XRAY")
	}
	for _, kind := range []string{"vless", "trojan"} {
		for _, host := range []string{"198.51.100.1", "2001:db8::1", "edge.example.com", "10.0.0.1", "fc00::1", "edge.test"} {
			t.Run(kind+"/"+host, func(t *testing.T) {
				n := Record{"type": kind, "server": host, "port": 443, "tls": false, "uuid": "11111111-1111-4111-8111-111111111111", "password": "fixture"}
				// Bypass only our policy to compare it with the native core's verdict.
				out, err := nodeOutbound(n, "proxy", false)
				if err != nil {
					t.Fatal(err)
				}
				raw, err := json.Marshal(Record{"outbounds": []any{out}})
				if err != nil {
					t.Fatal(err)
				}
				file := filepath.Join(t.TempDir(), "config.json")
				if err = os.WriteFile(file, raw, 0600); err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				output, nativeErr := exec.CommandContext(ctx, binary, "run", "-test", "-config", file).CombinedOutput()
				if ctx.Err() != nil {
					t.Fatal(ctx.Err())
				}
				_, policyErr := NodeOutbound(n, "proxy")
				if (nativeErr == nil) != (policyErr == nil) {
					t.Fatalf("policy %v native %v: %s", policyErr, nativeErr, output)
				}
			})
		}
	}
}
