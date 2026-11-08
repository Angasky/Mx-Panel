package subsource

import (
	"encoding/base64"
	"testing"
)

func TestMarkdownExternalSubscription(t *testing.T) {
	input := "[First](trojan://secret%29@example.net:443#First)[Second](hy2://secret@example.net:443#Second)\n`http://example.net:80#Third`"
	for _, content := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(content)
		if err != nil || len(batch.Nodes) != 3 || batch.SkippedCount != 0 {
			t.Fatal("wrapped subscription import failed", err, batch.SkippedCount)
		}
		if batch.Nodes[0]["password"] != "secret)" {
			t.Fatal("credential changed")
		}
	}
}

func TestLegacyEscapedExternalSubscription(t *testing.T) {
	input := "'trojan\\://pass%5C%40word\\@example\\.net:443#First'\n[second](hy2\\://secret\\@example\\.net:443#Second)"
	for _, content := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(content)
		if err != nil || len(batch.Nodes) != 2 || batch.SkippedCount != 0 {
			t.Fatal("legacy subscription rejected", err)
		}
		if batch.Nodes[0]["password"] != "pass\\@word" || batch.Nodes[0]["name"] != "First" {
			t.Fatal("credential or name changed")
		}
	}
}
