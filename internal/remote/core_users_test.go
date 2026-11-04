package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestReadCoreUserCountsOnlyBoundIdentity(t *testing.T) {
	user := Record{"id": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "email": "alice"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{user}}}
	binding := bindingFor(t, row, user)
	binding["inboundId"] = 17
	native, err := legacyNativeInbound("xray", row)
	if err != nil {
		t.Fatal(err)
	}
	const listen = "127.0.0.1:10085"
	state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{
		"listen": listen, "binary": "/usr/local/bin/xray", "users": []any{"alice"},
	}}
	doc := Record{
		"api":      Record{"tag": "mxioc-user-stats", "listen": listen, "services": []any{"StatsService"}},
		"inbounds": []any{native}, "stats": Record{},
		"policy": Record{"levels": Record{"0": Record{"statsUserUplink": true, "statsUserDownlink": true}}},
	}
	for _, drift := range []bool{false, true} {
		reads := 0
		run := func(_ context.Context, command string, _ int) (string, error) {
			if command == "base64 < '/usr/local/etc/xray/config.json'" {
				reads++
				raw, err := json.Marshal(doc)
				if drift && reads == 2 {
					raw = append(raw, '\n')
				}
				return base64.StdEncoding.EncodeToString(raw), err
			}
			return `{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"1234"},{"name":"user>>>other>>>traffic>>>uplink","value":"9000"}]}`, nil
		}
		result, err := readCoreUser(context.Background(), "xray", state, binding, run)
		if err != nil {
			t.Fatal(err)
		}
		if drift {
			if result["reading"] != nil || result["counterError"] == nil {
				t.Fatal("concurrent drift should invalidate the reading")
			}
		} else if reading, ok := result["reading"].(Record); !ok ||
			reading["source"] != "authenticated-client" || reading["up"] != int64(1234) || reading["down"] != int64(0) {
			t.Fatalf("unexpected reading: %v", result["reading"])
		}
	}
}

func TestCoreUserRemovalPlanVerifiesOwnershipAndPreservesOtherUsers(t *testing.T) {
	owner := Record{"email": "alice", "id": "3c5827c6-2f92-4861-a1f8-562d5388bca7"}
	other := Record{"email": "bob", "id": "30403cc4-583b-426a-8424-ec98489977b2"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{owner, other}}}
	binding := bindingFor(t, row, owner)
	binding["inboundId"] = 17
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			manual := Record{"tag": "unmanaged"}
			doc := Record{"inbounds": []any{native, manual}, "outbounds": []any{Record{"tag": "untouched"}}}
			state := legacyCoreState{Inbounds: []Record{row}}
			next, rows, err := planCoreUserRemoval(kind, state, doc, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			remaining := anyRecords(rows[0]["settings"].(Record)["clients"])
			if len(remaining) != 1 || remaining[0]["email"] != "bob" ||
				!sameCoreInbound(manual, anyRecords(next["inbounds"])[1]) {
				t.Fatal("removal changed unrelated entries")
			}
			if _, _, err := planCoreUserRemoval(kind, state, next, binding, false); err == nil {
				t.Fatal("changed remote configuration accepted without recovery intent")
			}
			retried, _, err := planCoreUserRemoval(kind, state, next, binding, true)
			if err != nil || !sameCoreInbound(next, retried) {
				t.Fatal("retry did not produce the same configuration")
			}
			again, _, err := planCoreUserRemoval(kind, legacyCoreState{Inbounds: rows}, next, binding, false)
			if err != nil || again != nil {
				t.Fatal("already removed user should be a no-op")
			}
			bad := bindingFor(t, row, other)
			bad["inboundId"], bad["userEmail"] = 17, "alice"
			if _, _, err := planCoreUserRemoval(kind, state, doc, bad, false); err == nil {
				t.Fatal("incorrect credential hash accepted")
			}
		})
	}
}
