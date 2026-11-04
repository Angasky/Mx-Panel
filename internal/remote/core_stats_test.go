package remote

import (
	"context"
	"errors"
	"testing"
)

func TestCoreCountersRequireLiveLocalAPIAndUniqueUsers(t *testing.T) {
	const address = "127.0.0.1:10085"
	stats := Record{"listen": address, "binary": "/usr/local/bin/xray", "users": []any{"alice"}}
	row := Record{"id": 17, "coreStatus": "present"}
	managed := Record{"tag": "mxioc-inbound-17", "settings": Record{"clients": []any{Record{"email": "alice"}}}}
	doc := Record{
		"api":   Record{"tag": "mxioc-user-stats", "listen": address, "services": []any{"StatsService"}},
		"stats": Record{}, "inbounds": []any{managed},
		"policy": Record{"levels": Record{"0": Record{"statsUserUplink": true, "statsUserDownlink": true}}},
	}
	inventory := Record{"inbounds": []any{row}}
	query := func(_ context.Context, cmd string, _ int) (string, error) {
		if cmd != "/usr/local/bin/xray api statsquery --server='127.0.0.1:10085' --pattern='user>>>'" {
			t.Fatalf("unexpected query: %s", cmd)
		}
		return `{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"9007199254740993"}]}`, nil
	}
	if err := readCoreCounters(context.Background(), "xray", doc, stats, inventory, query); err != nil {
		t.Fatal(err)
	}
	if row["up"] != int64(9007199254740993) || row["down"] != int64(0) {
		t.Fatal("verified counters missing or imprecise")
	}
	delete(row, "up")
	delete(row, "down")
	doc["inbounds"] = []any{managed, Record{"tag": "manual", "settings": managed["settings"]}}
	if err := readCoreCounters(context.Background(), "xray", doc, stats, inventory, query); err != nil || row["up"] != nil {
		t.Fatal("duplicated email should not be counted")
	}
	doc["inbounds"] = []any{managed}
	if err := readCoreCounters(context.Background(), "xray", doc, stats, inventory,
		func(context.Context, string, int) (string, error) { return "{}", errors.New("unavailable") }); err == nil || row["up"] != nil {
		t.Fatal("failed query must not produce zero")
	}
	stats["listen"] = "192.0.2.1:10085"
	if _, err := coreStatsAddress("xray", doc, stats); err == nil {
		t.Fatal("accepted non-loopback address")
	}
}

func TestSingBoxCountersRequireMatchingEnabledUser(t *testing.T) {
	row := Record{"id": 3, "coreStatus": "present"}
	api := Record{"listen": "127.0.0.1:10085", "stats": Record{"enabled": true, "users": []any{"other"}}}
	doc := Record{"experimental": Record{"v2ray_api": api}, "inbounds": []any{
		Record{"tag": "mxioc-inbound-3", "users": []any{Record{"name": "alice"}}},
	}}
	stats := Record{"listen": "127.0.0.1:10085", "binary": "/usr/local/bin/xray", "users": []any{"alice"}}
	inventory := Record{"inbounds": []any{row}}
	if _, err := coreStatsAddress("sing-box", doc, stats); err != nil {
		t.Fatal(err)
	}
	applyCoreCounters("sing-box", doc, stats, inventory, nil)
	if row["up"] != nil {
		t.Fatal("inactive counter should not appear")
	}
	api["stats"].(Record)["users"] = []any{"alice"}
	applyCoreCounters("sing-box", doc, stats, inventory, nil)
	if row["up"] != int64(0) {
		t.Fatal("a verified user without traffic should display zero")
	}
}
