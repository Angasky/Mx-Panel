package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func ownedRelayFixture(t *testing.T) (Record, Record) {
	t.Helper()
	doc, e := relayPatch(Record{"outbounds": []any{Record{"tag": "direct", "protocol": "freedom"}}, "routing": Record{"rules": []any{}}, "custom": true}, Record{"tag": "inbound-1"}, Record{"tag": "mxioc-relay-fixture", "protocol": "socks", "settings": Record{}})
	if e != nil {
		t.Fatal(e)
	}
	proof, e := relayOwnership(doc, "mxioc-relay-fixture", "inbound-1")
	if e != nil {
		t.Fatal(e)
	}
	proof["outboundTag"] = "mxioc-relay-fixture"
	proof["inboundId"] = 1
	return doc, proof
}
func TestStripRelayKeepsOtherResourcesAndRejectsChangedIdentity(t *testing.T) {
	doc, proof := ownedRelayFixture(t)
	next, changed, e := stripOwnedRelay(doc, proof)
	if e != nil || !changed || next["custom"] != true || len(next["outbounds"].([]any)) != 1 {
		t.Fatal(next, changed, e)
	}
	if len(doc["outbounds"].([]any)) != 2 {
		t.Fatal("input mutated")
	}
	if _, changed, e = stripOwnedRelay(next, proof); e != nil || changed {
		t.Fatal("idempotent cleanup failed", e)
	}
	doc["outbounds"].([]any)[1].(Record)["protocol"] = "http"
	if _, _, e = stripOwnedRelay(doc, proof); e == nil {
		t.Fatal("changed outbound deleted")
	}
	doc, proof = ownedRelayFixture(t)
	routing := doc["routing"].(Record)
	routing["rules"] = append(routing["rules"].([]any), Record{"outboundTag": "mxioc-relay-fixture", "inboundTag": []any{"another"}})
	if _, _, e = stripOwnedRelay(doc, proof); e == nil {
		t.Fatal("shared outbound deleted")
	}
	doc, proof = ownedRelayFixture(t)
	doc["routing"].(Record)["balancers"] = []any{Record{"selector": []any{"mxioc-relay-"}}}
	if _, _, e = stripOwnedRelay(doc, proof); e == nil {
		t.Fatal("prefix-selected outbound deleted")
	}
	if _, _, e = stripOwnedRelay(doc, Record{"outboundTag": "mxioc-relay-fixture"}); e == nil {
		t.Fatal("legacy record guessed")
	}
}
func TestCleanupRelayOnlyAfterConfirmedInboundAbsence(t *testing.T) {
	for _, present := range []bool{true, false} {
		doc, proof := ownedRelayFixture(t)
		writes := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/csrf-token":
				json.NewEncoder(w).Encode(Record{"success": true, "obj": "csrf"})
			case "/login":
				json.NewEncoder(w).Encode(Record{"success": true})
			case "/panel/api/inbounds/list":
				rows := []any{}
				if present {
					rows = append(rows, Record{"id": 1})
				}
				json.NewEncoder(w).Encode(Record{"success": true, "obj": rows})
			case "/panel/xray/":
				raw, _ := json.Marshal(doc)
				json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"xraySetting": string(raw)}})
			case "/panel/xray/update":
				writes++
				r.ParseForm()
				doc, _ = inboundObject(r.Form.Get("xraySetting"))
				json.NewEncoder(w).Encode(Record{"success": true})
			case "/panel/api/server/restartXrayService":
				json.NewEncoder(w).Encode(Record{"success": true})
			default:
				w.WriteHeader(404)
			}
		}))
		base, _ := url.Parse(server.URL + "/")
		p := newPanel(base, server.Client().Transport, Record{}, "", "token", NewPanelSession())
		e := cleanupPanelRelay(context.Background(), p, proof)
		if present {
			if e == nil || writes != 0 {
				t.Fatal("live inbound disconnected", e, writes)
			}
		} else {
			if e != nil || writes != 1 {
				t.Fatal("cleanup failed", e, writes)
			}
			if e = cleanupPanelRelay(context.Background(), p, proof); e != nil || writes != 1 {
				t.Fatal("cleanup retry rewrote config", e, writes)
			}
		}
		server.Close()
	}
}
func TestRelayRegistryRejectsMalformedAndRepeatedOwnership(t *testing.T) {
	for _, raw := range []any{Record{}, []any{"bad"}, []any{Record{"inboundId": 1, "outboundTag": "tag"}, Record{"inboundId": 1, "outboundTag": "other"}}} {
		if _, e := relayRecords(Record{"relays": raw}); e == nil {
			t.Fatal("invalid registry accepted")
		}
	}
}

func TestRelayDeleteRetainsDurableCleanupAndRetriesWithoutDeletingAgain(t *testing.T) {
	manager, serverID := certificateFixture(t)
	doc, proof := ownedRelayFixture(t)
	inbound := Record{"id": 1, "tag": "inbound-1", "port": 24001, "protocol": "vless", "enable": true, "settings": Record{"clients": []any{}}, "streamSettings": Record{"network": "tcp", "security": "none"}}
	if e := manager.recordRelay(serverID, inbound, value(proof["outboundTag"]), "active", proof); e != nil {
		t.Fatal(e)
	}
	expected, _ := InboundVersion(inbound)
	live := true
	deletes, writes := 0, 0
	failWrite := true
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf-token":
			json.NewEncoder(w).Encode(Record{"success": true, "obj": "csrf"})
		case "/login":
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/api/inbounds/list":
			rows := []any{}
			if live {
				rows = append(rows, inbound)
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": rows})
		case "/panel/api/inbounds/del/1":
			deletes++
			live = false
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/xray/":
			raw, _ := json.Marshal(doc)
			json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"xraySetting": string(raw)}})
		case "/panel/xray/update":
			writes++
			if failWrite {
				w.WriteHeader(500)
				return
			}
			r.ParseForm()
			doc, _ = inboundObject(r.Form.Get("xraySetting"))
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/api/server/restartXrayService":
			json.NewEncoder(w).Encode(Record{"success": true})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/")
	panel := newPanel(base, server.Client().Transport, Record{}, "", "token", NewPanelSession())
	record, _ := manager.Record(serverID)
	stored := anyRecords(record["relays"])[0]
	guardCalls := 0
	guard := func(Record) error { guardCalls++; return nil }
	if _, e := manager.deleteRelayInbound(context.Background(), panel, record, stored, 1, expected, guard); e == nil || deletes != 1 || live {
		t.Fatal("partial delete not reported", e, deletes)
	}
	reopened, e := Open(manager.root + "/..")
	if e != nil {
		t.Fatal(e)
	}
	record, _ = reopened.Record(serverID)
	stored = anyRecords(record["relays"])[0]
	if stored["deletePending"] != true || stored["status"] != "deleting" {
		t.Fatal("cleanup intent lost across restart")
	}
	failWrite = false
	result, e := reopened.deleteRelayInbound(context.Background(), panel, record, stored, 1, expected, guard)
	if e != nil || result["relayCleaned"] != true || deletes != 1 || writes != 2 || guardCalls != 2 {
		t.Fatal(result, e, deletes, writes, guardCalls)
	}
	record, _ = reopened.Record(serverID)
	if len(anyRecords(record["relays"])) != 0 {
		t.Fatal("completed relay metadata retained")
	}
}
