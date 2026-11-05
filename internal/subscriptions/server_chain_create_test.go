package subscriptions

import (
	"context"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type namedChainBackend struct {
	*relayBackend
	registry  []Record
	readings  map[string]Record
	landing   string
	template  string
	templates map[string]string
}

func (b *namedChainBackend) List() ([]remote.Record, error) { return b.registry, nil }
func (b *namedChainBackend) Inbounds(_ context.Context, server string) (Record, error) {
	return b.readings[server], nil
}
func (b *namedChainBackend) CreateRelay(ctx context.Context, server, profile string, payload Record) (Record, error) {
	b.landing = text(payload["landingLink"])
	b.template = text(payload["template"])
	if b.templates == nil {
		b.templates = map[string]string{}
	}
	b.templates[server] = b.template
	return b.relayBackend.CreateRelay(ctx, server, profile, payload)
}

func TestNamedChainCreationVerifiesSourcesAndRetriesWithoutDuplicateUsers(t *testing.T) {
	for _, choice := range []string{"", "vless-reality", "vmess-tcp"} {
		t.Run("choice="+choice, func(t *testing.T) { testNamedChainCreation(t, choice) })
	}
}

func testNamedChainCreation(t *testing.T, choice string) {
	c, base, _ := controllerFixture(t)
	entry := Record{"name": "entry", "type": "vless", "uuid": "3c5827c6-2f92-4861-a1f8-562d5388bca7",
		"server": "entry.example.net", "port": 443}
	exit := Record{"name": "exit", "type": "vless", "uuid": "30403cc4-583b-426a-8424-ec98489977b2",
		"server": "exit.example.net", "port": 443}
	readings := map[string]Record{}
	registry := []Record{}
	for _, node := range []Record{entry, exit} {
		id := text(node["name"])
		uri, err := links.Export(node)
		if err != nil {
			t.Fatal(err)
		}
		kind := "3x-ui"
		if id == "entry" {
			kind = "sing-box"
		}
		registry = append(registry, Record{"id": id, "nodeAddress": node["server"], "installType": kind})
		readings[id] = Record{"inbounds": []any{Record{"id": 1, "port": 443, "enable": true, "shareLinks": []any{uri}}}}
	}
	backend := &namedChainBackend{relayBackend: &relayBackend{templateBackend: &templateBackend{
		fakeBackend: base, created: map[string]int{},
	}}, registry: registry, readings: readings}
	c.Backend = backend
	if err := c.Repository.Mutate("clash", func(doc Record) error {
		doc["proxies"] = []any{entry, exit}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	request := Record{"name": "named relay", "entry": "entry", "exit": "exit",
		"operationId": strings.Repeat("b", 32), "groups": []any{"Proxy"}, "serverName": "example.net"}
	for _, invalid := range []any{"trojan-tls", true, Record{}} {
		request["singBoxTemplate"] = invalid
		if _, err := c.CreateServerChain(context.Background(), "clash", request); err == nil || backend.creates != 0 {
			t.Fatal("invalid ingress choice reached server creation")
		}
	}
	delete(request, "singBoxTemplate")
	if choice != "" {
		request["singBoxTemplate"] = choice
	}
	exitSnapshot := backend.readings["exit"]
	backend.readings["exit"] = backend.readings["entry"]
	if _, err := c.CreateServerChain(context.Background(), "clash", request); err == nil || backend.creates != 0 {
		t.Fatal("unverified exit should not create a relay")
	}
	backend.readings["exit"] = exitSnapshot
	for i := 0; i < 2; i++ {
		result, err := c.CreateServerChain(context.Background(), "clash", request)
		if err != nil || result["bound"] != true || backend.creates != 1 || backend.adds != 1 {
			t.Fatal(result, err)
		}
	}
	if !strings.Contains(backend.landing, "exit.example.net") {
		t.Fatal("used the wrong landing link")
	}
	want := choice
	if want == "" {
		want = "vmess-tcp"
	}
	if backend.template != want {
		t.Fatal("sing-box chain changed the requested or legacy ingress protocol")
	}
	state, err := c.Repository.State("clash")
	if err != nil || len(objects(state["serverChains"])) != 1 {
		t.Fatal("chain metadata missing or duplicated", err)
	}
	raw, err := c.Repository.Raw("clash")
	if err != nil || !strings.Contains(raw, "- named relay") {
		t.Fatal("named node missing from selected policy group", err)
	}
}
