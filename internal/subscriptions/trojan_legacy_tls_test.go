package subscriptions

import (
	"encoding/json"
	"testing"
	"time"
)

func TestLegacyTrojanXrayHADefaultsToTLS(t *testing.T) {
	source := rocketFixture() // Python-shaped Trojan records have no tls field.
	nodes := source.Document["proxies"].([]any)
	nodes[1].(Record)["sni"] = "tls.example.net"
	for _, format := range []string{"v2rayn-ha", "v2rayng-ha"} {
		out, err := Convert(source, format, time.Now())
		if err != nil || out.Count != 1 || len(out.Skipped) != 0 {
			t.Fatal("legacy group rejected", err)
		}
		var docs []Record
		if err := json.Unmarshal(out.Body, &docs); err != nil {
			t.Fatal(err)
		}
		for i, item := range docs[0]["outbounds"].([]any)[:2] {
			stream := item.(Record)["streamSettings"].(Record)
			if stream["security"] != "tls" {
				t.Fatal("legacy Trojan exported as plaintext")
			}
			tls := stream["tlsSettings"].(Record)
			if tls["allowInsecure"] == true || i == 1 && tls["serverName"] != "tls.example.net" {
				t.Fatal("TLS settings changed")
			}
		}
		raw, _ := json.Marshal(docs[0])
		checkXrayHAConfig(t, raw)
	}
	for _, node := range nodes {
		if _, exists := node.(Record)["tls"]; exists {
			t.Fatal("export mutated source")
		}
	}
}
