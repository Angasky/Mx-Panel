package subsource

import (
	"encoding/base64"
	"net/url"
	"testing"
)

func TestPythonEscapedBase64AndSpacedSnellPolicy(t *testing.T) {
	for _, raw := range []string{
		"name = snell , example.com, 443, psk=secret, version=5",
		"snell://secret@example.com:443?version=5#name",
	} {
		for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
			encoded := encoding.EncodeToString([]byte(raw))
			for _, source := range []string{encoded, url.QueryEscape(encoded)} {
				batch, err := Parse(source)
				if err != nil || len(batch.Nodes) != 1 || batch.Nodes[0]["psk"] != "secret" {
					t.Fatal("Python base64 subscription rejected", err, batch)
				}
			}
		}
	}
}
