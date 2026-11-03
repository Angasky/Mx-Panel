package subscriptions

import (
	"encoding/base64"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"strings"
	"testing"
	"time"
)

func rocketFixture() config.Subscription {
	return config.Subscription{Slug: strings.Repeat("a", 50), Document: Record{"proxies": []any{Record{"name": "primary", "type": "trojan", "server": "a.example.com", "port": 443, "password": "first-secret"}, Record{"name": "backup", "type": "trojan", "server": "b.example.com", "port": 443, "password": "second-secret"}}, "proxy-groups": []any{Record{"name": "HA", "type": "fallback", "proxies": []any{"primary", "backup"}}}}, Managed: Record{"failovers": []any{Record{"name": "HA", "status": "active", "interval": 30, "paths": []any{"primary", "backup"}, "exit": "fixed"}}, "serverChains": []any{Record{"name": "primary", "serverId": "s1", "inboundId": 1, "exit": "fixed"}, Record{"name": "backup", "serverId": "s2", "inboundId": 2, "exit": "fixed"}}, "remoteNodes": []any{Record{"serverId": "s1", "inboundId": 1, "status": "active"}, Record{"serverId": "s2", "inboundId": 2, "status": "active"}}}}
}
func TestRocketPairedExportsPreserveOrderCredentialsAndScope(t *testing.T) {
	// Fixed outputs from the legacy Python client_adapter.shadowrocket_name.
	if shadowrocketName("primary", strings.Repeat("a", 50), false) != "MX-N-13a41a0fa02345bc primary" || shadowrocketName("HA", strings.Repeat("a", 50), true) != "MX-HA-7764215dcead6d61 HA" {
		t.Fatal("Python namespace compatibility changed")
	}
	source := rocketFixture()
	nodes, err := Convert(source, "shadowrocket-ha", time.Now())
	if err != nil || nodes.Count != 2 {
		t.Fatal(nodes, err)
	}
	raw, _ := base64.StdEncoding.DecodeString(string(nodes.Body))
	uris := strings.Split(string(raw), "\n")
	names := []string{}
	for i, uri := range uris {
		node, err := links.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, text(node["name"]))
		want := []string{"first-secret", "second-secret"}[i]
		if node["password"] != want {
			t.Fatal("credential changed")
		}
	}
	conf, err := Convert(source, "shadowrocket-config", time.Now())
	if err != nil || conf.Count != 1 {
		t.Fatal(conf, err)
	}
	if !strings.Contains(string(conf.Body), " = fallback,"+strings.Join(names, ",")) || strings.Contains(string(conf.Body), "first-secret") || strings.Contains(string(conf.Body), source.Slug) {
		t.Fatal("policy names, order or secret isolation failed")
	}
	source.Slug = strings.Repeat("b", 50)
	other, _ := Convert(source, "shadowrocket-ha", time.Now())
	if string(other.Body) == string(nodes.Body) {
		t.Fatal("subscription namespaces collide")
	}
	if source.Document["proxies"].([]any)[0].(Record)["name"] != "primary" {
		t.Fatal("export mutated source")
	}
}
func TestRocketInvalidPathRejectsWholeGroup(t *testing.T) {
	for _, change := range []func(config.Subscription){
		func(s config.Subscription) { s.Managed["remoteNodes"].([]any)[1].(Record)["status"] = "revoked" },
		func(s config.Subscription) {
			s.Document["proxy-groups"].([]any)[0].(Record)["proxies"] = []any{"backup", "primary"}
		},
		func(s config.Subscription) { s.Managed["serverChains"].([]any)[1].(Record)["exit"] = "other" },
		func(s config.Subscription) { s.Document["proxies"].([]any)[1].(Record)["dialer-proxy"] = "primary" },
		func(s config.Subscription) { s.Managed["failovers"].([]any)[0].(Record)["interval"] = 30.5 },
	} {
		source := rocketFixture()
		change(source)
		result, err := Convert(source, "shadowrocket-config", time.Now())
		if err == nil || result.Count != 0 || len(result.Skipped) != 1 {
			t.Fatal("partial invalid group exported", result, err)
		}
	}
	label := shadowrocketName("[a],=b\nFINAL,DIRECT;#'\\\u2028", "scope", false)
	if strings.ContainsAny(label, "\n\r,=;#[]'\\\u2028") {
		t.Fatal("configuration injection")
	}
}
