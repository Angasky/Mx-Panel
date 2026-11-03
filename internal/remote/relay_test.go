package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func relayFixture(t *testing.T) (*Panel, Record, *Record, *int, *string) {
	t.Helper()
	original := Record{"outbounds": []any{Record{"tag": "direct", "protocol": "freedom"}}, "routing": Record{"rules": []any{Record{"type": "field", "domain": []any{"example.com"}, "outboundTag": "direct"}}}, "custom": Record{"keep": true}}
	updated, err := relayPatch(original, Record{"tag": "inbound-24001"}, Record{"tag": "mxioc-relay-fixture", "protocol": "socks", "settings": Record{}})
	if err != nil {
		t.Fatal(err)
	}
	current := original
	writes, restarts := 0, 0
	mode := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf-token":
			json.NewEncoder(w).Encode(Record{"success": true, "obj": "fixture-csrf"})
		case "/login":
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/xray/":
			raw, _ := json.Marshal(current)
			json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"xraySetting": string(raw)}})
		case "/panel/xray/update":
			writes++
			r.ParseForm()
			current, _ = inboundObject(r.Form.Get("xraySetting"))
			if mode == "disconnect" && writes == 1 {
				connection, _, _ := w.(http.Hijacker).Hijack()
				connection.Close()
				return
			}
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/api/server/restartXrayService":
			restarts++
			if (mode == "restart-failure" || mode == "external-change") && restarts == 1 {
				if mode == "external-change" {
					current["external"] = true
				}
				w.WriteHeader(500)
				return
			}
			json.NewEncoder(w).Encode(Record{"success": true})
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL + "/")
	p := newPanel(base, server.Client().Transport, Record{}, "", "fixture-token", NewPanelSession())
	return p, Record{"status": "prepared", "desired": Record{"original": original, "updated": updated}}, &current, &writes, &mode
}
func TestRelayPatchPreservesUnmanagedConfiguration(t *testing.T) {
	_, entry, _, _, _ := relayFixture(t)
	doc := entry["desired"].(Record)
	original := doc["original"].(Record)
	updated := doc["updated"].(Record)
	if len(original["outbounds"].([]any)) != 1 || len(updated["outbounds"].([]any)) != 2 || updated["custom"].(Record)["keep"] != true {
		t.Fatal("unmanaged config changed")
	}
	if _, err := relayPatch(updated, Record{"tag": "inbound-24001"}, Record{"tag": "other"}); err == nil {
		t.Fatal("existing inbound route overwritten")
	}
}
func TestRelayApplyVerifiesAndConfirmedRetryDoesNotWrite(t *testing.T) {
	p, entry, _, writes, _ := relayFixture(t)
	saved := 0
	persist := func(Record) error { saved++; return nil }
	if err := applyPanelRelay(context.Background(), p, entry, persist); err != nil || entry["status"] != "confirmed" || *writes != 1 || saved != 2 {
		t.Fatal(err, entry["status"], *writes, saved)
	}
	if err := applyPanelRelay(context.Background(), p, entry, persist); err != nil || *writes != 1 {
		t.Fatal("confirmed retry rewrote config", err)
	}
}
func TestRelayFailureRollbackAndConcurrentChanges(t *testing.T) {
	for _, mode := range []string{"disconnect", "restart-failure", "external-change"} {
		t.Run(mode, func(t *testing.T) {
			p, entry, current, writes, behavior := relayFixture(t)
			*behavior = mode
			err := applyPanelRelay(context.Background(), p, entry, func(Record) error { return nil })
			if err == nil {
				t.Fatal("failure reported success")
			}
			if mode == "external-change" {
				if *writes != 1 || (*current)["external"] != true || entry["status"] != "sent" {
					t.Fatal("concurrent config overwritten")
				}
			} else {
				hash, _ := identity(*current)
				old, _ := identity(entry["desired"].(Record)["original"])
				if hash != old || *writes != 2 || entry["status"] != "prepared" {
					t.Fatal("rollback not confirmed", *writes, entry["status"])
				}
			}
		})
	}
	p, entry, _, writes, _ := relayFixture(t)
	if err := applyPanelRelay(context.Background(), p, entry, func(Record) error { return errors.New("disk full") }); err == nil || *writes != 0 {
		t.Fatal("write sent without durable intent")
	}
}
