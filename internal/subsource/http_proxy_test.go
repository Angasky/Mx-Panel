package subsource

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestPythonHTTPProxyExternalSubscription(t *testing.T) {
	input := "https://u:p@example.net?host=proxy.example&ua=Agent%20One&name-cert-verify=cert.example&fingerprint=" + strings.Repeat("ab", 32) + "#Legacy\nhttp://example.net?host=bad%0D%0Avalue"
	for _, body := range []string{input, base64.StdEncoding.EncodeToString([]byte(input))} {
		batch, err := Parse(body)
		if err != nil || len(batch.Nodes) != 1 || batch.SkippedCount != 1 {
			t.Fatal(batch, err)
		}
		n := batch.Nodes[0]
		if n["port"] != 443 || n["name-cert-verify"] != "cert.example" || n["headers"].(map[string]any)["User-Agent"] != "Agent One" || n["fingerprint"] == nil {
			t.Fatal("HTTP source options lost")
		}
	}
}
