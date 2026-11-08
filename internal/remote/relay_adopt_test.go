package remote

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLegacyRelayExplicitEvidence(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-outbound", "wrong-route", "stale-inbound", "shared-route", "missing-route", "wrong-registration", "conflicting-proof"} {
		t.Run(scenario, func(t *testing.T) {
			live, proof := ownedRelayFixture(t)
			row := Record{"id": 1, "tag": "inbound-1", "port": 24001, "protocol": "vless", "settings": Record{}}
			version, err := InboundVersion(row)
			if err != nil {
				t.Fatal(err)
			}
			var outbound, route Record
			for _, r := range anyRecords(live["outbounds"]) {
				if r["tag"] == proof["outboundTag"] {
					outbound = r
				}
			}
			routing := live["routing"].(Record)
			for _, r := range anyRecords(routing["rules"]) {
				if r["outboundTag"] == proof["outboundTag"] {
					route = r
				}
			}
			if outbound == nil || route == nil {
				t.Fatal("fixture lacks resources")
			}
			// Clone evidence before changing the live side.
			raw, _ := canonicalJSON(Record{"outbound": outbound, "route": route})
			evidence, err := inboundObject(string(raw))
			if err != nil {
				t.Fatal(err)
			}
			legacy := Record{"inboundId": 1, "outboundTag": proof["outboundTag"]}
			record := Record{"relays": []any{legacy}}
			switch scenario {
			case "wrong-outbound":
				outbound["protocol"] = "different"
			case "wrong-route":
				route["type"] = "different"
			case "stale-inbound":
				version = strings.Repeat("0", 64)
			case "shared-route":
				routing["rules"] = append(routing["rules"].([]any), Record{"type": "field", "inboundTag": []any{"another-inbound"}, "outboundTag": proof["outboundTag"]})
			case "missing-route":
				routing["rules"] = []any{}
			case "wrong-registration":
				legacy["outboundTag"] = "mxioc-relay-other"
			case "conflicting-proof":
				legacy["routeHash"] = strings.Repeat("0", 64)
			}
			got, err := legacyRelayEvidence(record, row, live, 1, version, evidence)
			if scenario != "success" {
				if err == nil {
					t.Fatal("unverified evidence accepted")
				}
				return
			}
			if err != nil || got["outboundHash"] != proof["outboundHash"] || got["routeHash"] != proof["routeHash"] {
				t.Fatal(got, err)
			}
			manager, id := certificateFixture(t)
			if err = manager.recordRelay(id, row, value(got["outboundTag"]), "active", got); err != nil {
				t.Fatal(err)
			}
			reopened, err := Open(filepath.Dir(manager.root))
			if err != nil {
				t.Fatal(err)
			}
			saved, err := reopened.Record(id)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = legacyRelayEvidence(saved, row, live, 1, version, evidence); err != nil {
				t.Fatal("receipt replay failed", err)
			}
			next, changed, err := stripOwnedRelay(live, got)
			if err != nil || !changed || containsConfigString(next, value(got["outboundTag"])) {
				t.Fatal("adopted proof cannot clean original resource", err)
			}
		})
	}
}
