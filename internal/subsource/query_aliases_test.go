package subsource

import (
	"encoding/base64"
	"testing"
)

func TestLegacyTransportAliasesInSubscription(t *testing.T) {
	input := "vless://11111111-1111-4111-8111-111111111111@example.net:443?security=tls&network=grpc&peer=tls.example&service_name=vpn#Legacy\n" +
		"trojan://password@example.net:443?network=ws#Default\n" +
		"trojan://password@example.net:443?type=ws&network=grpc#Conflict\n"
	for _, content := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(content)
		if err != nil || len(batch.Nodes) != 2 || batch.SkippedCount != 1 {
			t.Fatalf("unexpected import: %#v, %v", batch, err)
		}
		node := batch.Nodes[0]
		if node["servername"] != "tls.example" || node["grpc-opts"].(map[string]any)["grpc-service-name"] != "vpn" {
			t.Fatal("transport settings lost")
		}
		if batch.Nodes[1]["ws-opts"].(map[string]any)["path"] != "/" {
			t.Fatal("default path lost")
		}
	}
}
