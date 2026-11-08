package subsource

import (
	"encoding/base64"
	"testing"
)

func TestLegacyIPv6ExternalSubscription(t *testing.T) {
	input := "trojan://secret@2001:db8::1:443#IPv6\nhttp://bad:authority:443#Bad"
	for _, body := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(body)
		if err != nil || len(batch.Nodes) != 1 || batch.SkippedCount != 1 {
			t.Fatal("unexpected import result", err)
		}
		if batch.Nodes[0]["server"] != "2001:db8::1" || batch.Nodes[0]["password"] != "secret" {
			t.Fatal("IPv6 import changed address or credential")
		}
	}
}
