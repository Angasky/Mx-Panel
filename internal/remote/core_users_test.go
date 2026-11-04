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
