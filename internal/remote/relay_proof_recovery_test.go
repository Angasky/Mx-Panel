package remote

import (
	"strings"
	"testing"
)

func TestRecoverRelayProofRequiresBothJournalsAndExactLiveResources(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	server, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	record, err := m.Record(value(server["id"]))
	if err != nil {
		t.Fatal(err)
	}
	baseKey := strings.Repeat("a", 64)
	tag := "mxioc-relay-" + baseKey[:16]
	inbound := Record{"id": 1, "tag": "inbound-1", "port": 24001, "protocol": "vless", "settings": Record{}}
	relay := Record{"inboundId": 1, "outboundTag": tag, "status": "active"}
	original := Record{"outbounds": []any{Record{"tag": "direct", "protocol": "freedom"}}, "routing": Record{"rules": []any{}}}
	live, err := relayPatch(original, inbound, Record{"tag": tag, "protocol": "socks", "settings": Record{}})
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := EndpointIdentity(inbound)
	if err != nil {
		t.Fatal(err)
	}
	base := Record{"serverId": record["id"], "scope": "profile", "revision": createServerRevision(record),
		"requestHash": "fixture", "status": "confirmed", "inboundId": 1, "endpointHash": endpoint, "desired": inbound}
	if err := m.persistCreate(baseKey, base); err != nil {
		t.Fatal(err)
	}
	if _, err := m.recoverRelayProof(record, relay, inbound, live); err == nil {
		t.Fatal("inbound journal alone should not prove relay ownership")
	}
	relayKey, err := identity([]any{baseKey, "relay"})
	if err != nil {
		t.Fatal(err)
	}
	entry := Record{"serverId": record["id"], "scope": "profile", "revision": createServerRevision(record),
		"requestHash": "fixture", "status": "confirmed", "desired": Record{"original": original, "updated": live}}
	if err := m.persistCreate(relayKey, entry); err != nil {
		t.Fatal(err)
	}
	proof, err := m.recoverRelayProof(record, relay, inbound, live)
	if err != nil || proof["outboundHash"] == nil || proof["routeHash"] == nil {
		t.Fatal("confirmed journals did not prove ownership", err)
	}
	inbound["port"] = 24002
	if _, err := m.recoverRelayProof(record, relay, inbound, live); err == nil {
		t.Fatal("changed endpoint accepted")
	}
	inbound["port"] = 24001
	live["outbounds"].([]any)[1].(Record)["protocol"] = "http"
	if _, err := m.recoverRelayProof(record, relay, inbound, live); err == nil {
		t.Fatal("changed outbound accepted")
	}
}
