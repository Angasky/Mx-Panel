package subscriptions

import (
	"bytes"
	"context"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func TestSS2022SubscriptionsKeepSeparateCredentialsAndExpiry(t *testing.T) {
	for _, method := range []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm"} {
		t.Run(method, func(t *testing.T) { testShadowsocksSubscriptions(t, method, false) })
	}
}

func TestSSAEADSubscriptionsKeepSeparateCredentialsAndExpiry(t *testing.T) {
	for _, method := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(method, func(t *testing.T) { testShadowsocksSubscriptions(t, method, true) })
	}
}

func testShadowsocksSubscriptions(t *testing.T, method string, classic bool) {
	size := 32
	if method == "2022-blake3-aes-128-gcm" {
		size = 16
	}
	c, b, root := controllerFixture(t)
	b.kind = "xray"
	key := func(v byte) string {
		raw := bytes.Repeat([]byte{v}, size)
		if classic {
			return base64.RawURLEncoding.EncodeToString(raw)
		}
		return base64.StdEncoding.EncodeToString(raw)
	}
	row := Record{"id": 1, "tag": "mxioc-inbound-1", "goCreateKey": "fixture", "goSS2022Guard": key(2), "remark": "SS2022", "protocol": "shadowsocks", "port": 24001, "enable": true, "settings": Record{"method": method, "password": key(1), "clients": []any{}}, "streamSettings": Record{"network": "tcp", "security": "none"}}
	if classic {
		delete(row, "goSS2022Guard")
		row["goSSAEADGuard"] = key(2)
	}
	b.rows = []Record{row}
	other, err := c.Repository.CreateProfile(Record{"name": "other"})
	if err != nil {
		t.Fatal(err)
	}
	profiles := []string{"clash", text(other["id"])}
	for _, id := range profiles {
		result, err := c.Batch(context.Background(), id, "s", []int{1})
		if err != nil || result["succeeded"] != 1 {
			t.Fatal("SS2022 import failed", result, err)
		}
	}
	clients := objects(row["settings"].(Record)["clients"])
	if len(clients) != 2 || clients[0]["password"] == clients[1]["password"] || clients[0]["email"] == clients[1]["email"] {
		t.Fatal("subscriptions share credentials")
	}
	for i, id := range profiles {
		snapshot, err := c.Repository.Snapshot(id)
		if err != nil {
			t.Fatal(err)
		}
		nodes := objects(snapshot["nodes"])
		if len(nodes) != 1 {
			t.Fatal("subscription node missing")
		}
		node := nodes[0]["config"].(Record)
		expected := text(clients[i]["password"])
		if !classic {
			expected = key(1) + ":" + expected
		}
		if node["cipher"] != method || node["password"] != expected || strings.Contains(text(node["password"]), key(2)) {
			t.Fatal("wrong SS2022 credential export")
		}
	}
	// Reopen persisted subscription state and repeat the import: neither a
	// new password nor another local node should be created.
	now := c.Now
	c = New(&config.Repository{Root: root}, b)
	c.Now = now
	c.started.Store(true)
	result, err := c.Batch(context.Background(), profiles[0], "s", []int{1})
	if err != nil || result["existing"] != 1 || b.adds != 2 {
		t.Fatal("retry duplicated SS2022 user", result, err)
	}
	b.stats[text(clients[0]["email"])] = Record{"up": int64(100), "down": int64(200), "source": "authenticated-client"}
	for i := 0; i < 3; i++ {
		if _, err := c.Sync(context.Background(), profiles[0]); err != nil {
			t.Fatal(err)
		}
	}
	first, err := c.Info(profiles[0])
	if err != nil || first["used"] != int64(300) {
		t.Fatal("idle or isolated accounting failed", first, err)
	}
	second, err := c.Info(profiles[1])
	if err != nil || second["used"] != int64(0) {
		t.Fatal("traffic charged to another subscription", err)
	}
	if err := c.Repository.UpdateState(profiles[0], func(p Record) error { traffic(p)["expire"] = int64(1); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Sync(context.Background(), profiles[0]); err != nil {
		t.Fatal(err)
	}
	remaining := objects(row["settings"].(Record)["clients"])
	if len(remaining) != 1 || remaining[0]["password"] != clients[1]["password"] {
		t.Fatal("expiry affected another subscription")
	}
}
