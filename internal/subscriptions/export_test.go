package subscriptions

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestClientExportFilteringSnellPasswordAndUsageNodes(t *testing.T) {
	now := time.Unix(1800000000, 0)
	source := config.Subscription{Slug: strings.Repeat("a", 50), Document: Record{"proxies": []any{
		Record{"name": "HY2", "type": "hysteria2", "server": "192.0.2.1", "port": 24443, "password": "hy2-pass", "sni": "cdn.example.com"},
		Record{"name": "Snell", "type": "snell", "server": "2001:db8::1", "port": 24444, "psk": "密码+/s:ecret", "version": 5},
		Record{"name": "chain", "type": "hysteria2", "server": "192.0.2.2", "port": 24445, "password": "chain-pass", "dialer-proxy": "HY2"},
	}}, Traffic: Record{"configured": true, "used": int64(1024), "total": int64(50 * 1024 * 1024 * 1024), "remaining": int64(50*1024*1024*1024 - 1024), "expire": now.Unix() + 86401}}
	result, err := Convert(source, "shadowrocket", now)
	if err != nil || result.Count != 2 || len(result.Skipped) != 1 {
		t.Fatal(result, err)
	}
	raw, err := base64.StdEncoding.DecodeString(string(result.Body))
	if err != nil {
		t.Fatal(err)
	}
	rows := strings.Split(string(raw), "\n")
	if len(rows) != 5 {
		t.Fatal("missing information or real nodes")
	}
	for _, uri := range rows[:3] {
		node, err := links.Parse(uri)
		if err != nil || node["server"] != "127.0.0.1" || text(node["port"]) != "9" {
			t.Fatal("information node points at real endpoint", node, err)
		}
	}
	var snell Record
	for _, uri := range rows[3:] {
		node, err := links.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		if node["type"] == "snell" {
			snell = node
		}
	}
	if snell == nil || snell["psk"] != "密码+/s:ecret" {
		t.Fatal("Snell password lost", snell)
	}
	for _, format := range []string{"v2rayn", "v2rayng", "v2ray"} {
		result, err := Convert(source, format, now)
		if err != nil || result.Count != 1 || len(result.Skipped) != 2 {
			t.Fatal(format, result, err)
		}
	}
	source.Traffic = Record{"configured": false}
	result, err = Convert(source, "shadowrocket", now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ = base64.StdEncoding.DecodeString(string(result.Body))
	if strings.Contains(string(raw), "00000000-0000-4000-8000-000000000000") || len(strings.Split(string(raw), "\n")) != 2 {
		t.Fatal("unconfigured usage fabricated")
	}
	if _, err = Convert(source, "v2rayn-ha", now); err == nil {
		t.Fatal("unmigrated failover silently downgraded")
	}
}

func TestHAExportsIncludePythonUsageLabel(t *testing.T) {
	for _, tc := range []struct {
		info  Record
		label string
	}{
		{Record{"configured": true, "used": int64(1024), "remaining": int64(1 << 30), "expire": int64(0)}, "已用 1.00 KiB · 剩余 1.00 GiB · 到期 1970-01-01 00:00 UTC"},
		{Record{"configured": true, "used": int64(1 << 40)}, "已用 1.00 TiB · 剩余 不限量 · 到期 长期有效"},
		{Record{"configured": false}, ""},
	} {
		source := rocketFixture()
		source.Traffic = tc.info
		for _, format := range []string{"v2rayn-ha", "v2rayng-ha", "shadowrocket-config"} {
			result, err := Convert(source, format, time.Unix(0, 0))
			if err != nil {
				t.Fatal(format, err)
			}
			if format == "shadowrocket-config" {
				if tc.label != "" && !strings.Contains(string(result.Body), "# "+tc.label+"\n") {
					t.Fatal("usage comment missing", string(result.Body))
				}
				if tc.label == "" && strings.Contains(string(result.Body), "已用") {
					t.Fatal("fabricated usage")
				}
			} else {
				var docs []Record
				if err := json.Unmarshal(result.Body, &docs); err != nil {
					t.Fatal(err)
				}
				want := "HA"
				if tc.label != "" {
					want += " | " + tc.label
				}
				if len(docs) != 1 || docs[0]["remarks"] != want {
					t.Fatal("remarks", docs)
				}
			}
		}
	}
}

func TestUsageNodesIndependentRemaining(t *testing.T) {
	for _, tc := range []struct {
		total, remaining any
		want             string
	}{
		{int64(1024), nil, "不限量"}, {nil, int64(1 << 30), "1.00 GB"},
	} {
		nodes := usageNodes(Record{"configured": true, "used": int64(0), "total": tc.total, "remaining": tc.remaining}, time.Unix(0, 0))
		if nodes[1]["name"] != "订阅信息 · 剩余流量 "+tc.want {
			t.Fatal(nodes)
		}
	}
}
