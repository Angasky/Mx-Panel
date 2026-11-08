package subsource

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestCertificatePinsInExternalSubscription(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	input := "hysteria2://secret@example.net:443?pinSHA256=" + pin + "#Pinned\n" +
		"hysteria2://secret@example.net:443?pinSHA256=private-secret#Invalid"
	for _, body := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(body)
		if err != nil || len(batch.Nodes) != 1 || batch.SkippedCount != 1 {
			t.Fatal(batch, err)
		}
		if strings.ReplaceAll(batch.Nodes[0]["fingerprint"].(string), ":", "") != strings.ToUpper(pin) {
			t.Fatal("external pin changed")
		}
		if strings.Contains(strings.Join(batch.Skipped, ""), "private-secret") {
			t.Fatal("diagnostic leaked input")
		}
	}
}
