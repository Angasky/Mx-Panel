package subsource

import (
	"encoding/base64"
	"strings"
	"testing"
)

const sourceMieru = "mierus://user:fixture-secret@example.com?profile=Mieru&port=2999&port=3000-3002&protocol=TCP&protocol=UDP"

func TestMieruSourceExpansionIsAtomicAndBounded(t *testing.T) {
	text := sourceMieru + "\n" + strings.Replace(sourceMieru, "protocol=UDP", "protocol=QUIC", 1)
	for _, value := range []string{text, base64.StdEncoding.EncodeToString([]byte(text))} {
		batch, err := Parse(value)
		if err != nil || len(batch.Nodes) != 2 || batch.SkippedCount != 1 {
			t.Fatal("multi-binding partial validation", batch, err)
		}
		if batch.Nodes[1]["port-range"] != "3000-3002" || batch.Nodes[1]["transport"] != "UDP" {
			t.Fatal("range/transport lost")
		}
		for _, message := range batch.Skipped {
			if strings.Contains(message, "fixture-secret") {
				t.Fatal("credential leaked")
			}
		}
	}
	yaml := `proxies:
- {name: native, type: mieru, server: example.com, port-range: 2999-3002, username: user, password: fixture-secret, transport: udp, custom: {keep: true}}
- {name: invalid, type: mieru, server: example.com, port-range: 3000-2999, username: user, password: fixture-secret}
`
	batch, err := Parse(yaml)
	if err != nil || len(batch.Nodes) != 1 || batch.SkippedCount != 1 || batch.Nodes[0]["custom"].(map[string]any)["keep"] != true {
		t.Fatal(batch, err)
	}
	if _, err = Parse(strings.Repeat(sourceMieru+"\n", 10001)); err == nil {
		t.Fatal("expanded node count limit ignored")
	}
}
