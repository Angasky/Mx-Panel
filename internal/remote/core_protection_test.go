package remote

import "testing"

func TestCoreWritePreservesManagedInbounds(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			previous := []byte(`{"inbounds":[{"tag":"mxioc-inbound-17","settings":{"clients":[{"id":"original"}]}}]}`)
			managed := Record{"tag": "mxioc-inbound-17", "settings": Record{"clients": []any{Record{"id": "original"}}}}
			candidate := Record{"inbounds": []any{Record{"tag": "manual"}, managed}}
			if _, err := CoreWriteScript(kind, previous, candidate); err != nil {
				t.Fatal(err)
			}
			for label, rows := range map[string][]any{
				"remove":    {Record{"tag": "manual"}},
				"replace":   {Record{"tag": "mxioc-inbound-17"}},
				"duplicate": {managed, managed},
				"forge":     {managed, Record{"tag": "mxioc-inbound-18"}},
			} {
				if _, err := CoreWriteScript(kind, previous, Record{"inbounds": rows}); err == nil {
					t.Errorf("%s: expected protected inbound error", label)
				}
			}
			if _, err := CoreWriteScript(kind, previous, Record{}); err == nil {
				t.Error("omitting inbounds should not remove managed entries")
			}
		})
	}
}
