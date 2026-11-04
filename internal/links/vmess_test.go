package links

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"testing"
)

func TestVMessGRPCPreservesTLSOptions(t *testing.T) {
	const v2rayN = `{"v":"2","ps":"gRPC","add":"vpn.example.net","port":"443","id":"22453845-ff1a-471d-8214-25952a9348a6","aid":"0","scy":"auto","net":"grpc","type":"none","path":"test/service","tls":"tls","sni":"tls.example.net","alpn":"h2,http/1.1","fp":"chrome","insecure":"1"}`
	node, err := Parse("vmess://" + base64.StdEncoding.EncodeToString([]byte(v2rayN)))
	if err != nil {
		t.Fatal(err)
	}
	uri, err := Export(node)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := decode64(uri[len("vmess://"):])
	var payload map[string]any
	if err != nil || json.Unmarshal([]byte(raw), &payload) != nil {
		t.Fatal("invalid share payload", err)
	}
	for field, expected := range map[string]string{"net": "grpc", "path": "test/service", "sni": "tls.example.net",
		"alpn": "h2,http/1.1", "fp": "chrome", "insecure": "1"} {
		if payload[field] != expected {
			t.Errorf("%s lost", field)
		}
	}
	restored, err := Parse(uri)
	if err != nil || !reflect.DeepEqual(node, restored) {
		t.Fatal("VMess options changed on round trip", err)
	}
}

func TestShareLinkRejectsUnrepresentableTransportOptions(t *testing.T) {
	for _, kind := range []string{"vmess", "vless", "trojan"} {
		node := map[string]any{"type": kind, "server": "example.net", "port": 443, "network": "grpc",
			"grpc-opts": map[string]any{"grpc-service-name": "test", "grpc-multi-mode": true}}
		if _, err := Export(node); err == nil {
			t.Errorf("%s exported a lossy gRPC link", kind)
		}
		node["network"] = "ws"
		node["ws-opts"] = map[string]any{"headers": map[string]any{"Authorization": "fixture-secret"}}
		if _, err := Export(node); err == nil {
			t.Errorf("%s exported a lossy WebSocket link", kind)
		}
	}
}
