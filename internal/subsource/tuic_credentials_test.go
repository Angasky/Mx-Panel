package subsource

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestTUICQueryCredentialsInExternalSubscriptions(t *testing.T) {
	input := "tuic://11111111-1111-4111-8111-111111111111@example.net:443?password=fixture-secret&congestion-controller=cubic&udp-relay-mode=quic#Legacy\n" +
		"tuic://11111111-1111-4111-8111-111111111111:private-secret@example.net:443?password=conflict#Bad"
	for _, content := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(content)
		if err != nil || len(batch.Nodes) != 1 || batch.SkippedCount != 1 {
			t.Fatal("unexpected subscription result", err)
		}
		if batch.Nodes[0]["password"] != "fixture-secret" || batch.Nodes[0]["udp-relay-mode"] != "quic" {
			t.Fatal("credential or transport lost")
		}
		if strings.Contains(strings.Join(batch.Skipped, ""), "private-secret") {
			t.Fatal("diagnostic exposed credentials")
		}
	}
}

func TestQUICDefaultsThroughExternalSubscription(t *testing.T) {
	batch, err := Parse("hy2://secret@example.net:443#HY2\ntuic://11111111-1111-4111-8111-111111111111:secret@example.net:443#TUIC")
	if err != nil || len(batch.Nodes) != 2 {
		t.Fatal("QUIC subscription parse failed", err)
	}
	if batch.Nodes[0]["alpn"].([]any)[0] != "h3" {
		t.Fatal("HY2 default lost")
	}
	tuic := batch.Nodes[1]
	if tuic["congestion-controller"] != "bbr" || tuic["udp-relay-mode"] != "native" || tuic["alpn"] != nil {
		t.Fatal("TUIC defaults changed")
	}
}
