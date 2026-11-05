package subscriptions

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestFailoverDraftResumesWithOrderedPaths(t *testing.T) {
	for _, choice := range []string{"", "vless-reality", "vmess-tcp"} {
		t.Run("choice="+choice, func(t *testing.T) { testFailoverDraftResume(t, choice) })
	}
}

func testFailoverDraftResume(t *testing.T, choice string) {
	c, base, _ := controllerFixture(t)
	nodes, registry, readings := []any{}, []Record{}, map[string]Record{}
	names := []string{"first", "second", "exit"}
	ids := []string{"3c5827c6-2f92-4861-a1f8-562d5388bca7", "30403cc4-583b-426a-8424-ec98489977b2", "94f022d0-9ab0-4664-96de-82aca7677c74"}
	for i, name := range names {
		host := name + ".example.net"
		node := Record{"name": name, "type": "vless", "uuid": ids[i], "server": host, "port": 443}
		uri, err := links.Export(node)
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, node)
		registry = append(registry, Record{"id": name, "host": host, "installType": []string{"xray", "sing-box", "3x-ui"}[i]})
		readings[name] = Record{"inbounds": []any{Record{"id": 1, "port": 443, "enable": true, "shareLinks": []any{uri}}}}
	}
	if err := c.Repository.Mutate("clash", func(doc Record) error { doc["proxies"] = nodes; return nil }); err != nil {
		t.Fatal(err)
	}
	backend := &namedChainBackend{relayBackend: &relayBackend{templateBackend: &templateBackend{
		fakeBackend: base, created: map[string]int{},
	}}, registry: registry, readings: readings}
	c.Backend = backend
	request := Record{"name": "ordered", "entries": []any{"second", "first"}, "exit": "exit", "groups": []any{"Proxy"},
		"interval": 30, "port": "", "serverName": "example.net", "operationId": strings.Repeat("c", 32)}
	if choice != "" {
		request["singBoxTemplate"] = choice
	}
	first := readings["first"]
	readings["first"] = Record{"inbounds": []any{}}
	if _, err := c.CreateFailover(context.Background(), "clash", request); err == nil || backend.creates != 1 || backend.adds != 1 {
		t.Fatal("partial failover not recorded correctly", err)
	}
	state, err := c.Repository.State("clash")
	if err != nil || len(objects(state["failovers"])) != 0 || len(objects(state["failoverDrafts"])) != 1 {
		t.Fatal("unfinished group exposed as active", err)
	}
	raw, _ := c.Repository.Raw("clash")
	if strings.Contains(raw, "type: fallback") {
		t.Fatal("unfinished fallback group entered the subscription")
	}
	readings["first"] = first
	draft := objects(state["failoverDrafts"])[0]
	want := choice
	if want == "" {
		want = "vmess-tcp"
	}
	if backend.templates["second"] != want || text(draft["singBoxTemplate"]) != choice {
		t.Fatal("failover did not preserve its explicit or legacy sing-box ingress")
	}
	altered := Record{}
	for k, v := range draft {
		altered[k] = v
	}
	if want == "vmess-tcp" {
		altered["singBoxTemplate"] = "vless-reality"
	} else {
		altered["singBoxTemplate"] = "vmess-tcp"
	}
	if _, err := c.CreateFailover(context.Background(), "clash", altered); err == nil || backend.creates != 1 {
		t.Fatal("changed ingress rewrote a partially created failover")
	}
	for i := 0; i < 2; i++ {
		result, err := c.CreateFailover(context.Background(), "clash", draft)
		if err != nil || result["status"] != "active" || backend.creates != 2 || backend.adds != 2 ||
			!reflect.DeepEqual(result["paths"], []any{"ordered / 1", "ordered / 2"}) {
			t.Fatal(result, err)
		}
	}
	state, err = c.Repository.State("clash")
	if err != nil || len(objects(state["failovers"])) != 1 || len(objects(state["failoverDrafts"])) != 0 {
		t.Fatal("expected one active group", err)
	}
}
