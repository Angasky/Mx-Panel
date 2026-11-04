package subscriptions

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
)

type failoverDeleteBackend struct {
	*fakeBackend
	failServer string
	writes     []string
}

func (b *failoverDeleteBackend) DeleteNamedRelay(_ context.Context, server string, id int, _ string, guard func(Record) error) (Record, error) {
	for i, row := range b.rows {
		if text(row["id"]) != text(id) {
			continue
		}
		if err := guard(clone(row)); err != nil {
			return nil, err
		}
		b.writes = append(b.writes, server)
		if server == b.failServer {
			return nil, errors.New("fixture remote failure")
		}
		b.rows = append(b.rows[:i], b.rows[i+1:]...)
		return Record{"deleted": true}, nil
	}
	if err := guard(nil); err != nil {
		return nil, err
	}
	return Record{"deleted": true}, nil
}

func TestDeleteFailoverDetachesRulesAndResumesRemainingPaths(t *testing.T) {
	c, base, _ := controllerFixture(t)
	ctx := context.Background()
	backend := &failoverDeleteBackend{fakeBackend: base, failServer: "backup"}
	c.Backend = backend
	for i, server := range []string{"primary", "backup"} {
		if _, err := c.Batch(ctx, "clash", server, []int{i + 1}); err != nil {
			t.Fatal(err)
		}
	}
	state, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	paths, chains := []any{}, []any{}
	for _, b := range objects(state["remoteNodes"]) {
		names, _ := b["importedNames"].([]any)
		paths = append(paths, names[0])
		chains = append(chains, Record{"name": names[0], "serverId": b["serverId"], "inboundId": b["inboundId"]})
	}
	if err := c.Repository.Mutate("clash", func(doc Record) error {
		doc["proxy-groups"] = append(doc["proxy-groups"].([]any), Record{"name": "HA", "type": "fallback", "proxies": paths})
		doc["rules"] = []any{"DOMAIN-SUFFIX,example.net,HA", "MATCH,DIRECT"}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		p["serverChains"] = chains
		p["failovers"] = []any{Record{"name": "HA", "status": "active", "paths": paths}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteFailover(ctx, "clash", "HA"); err == nil {
		t.Fatal("partial failure accepted")
	}
	raw, err := c.Repository.Raw("clash")
	if err != nil || strings.Contains(raw, "type: fallback") || !strings.Contains(raw, "DOMAIN-SUFFIX,example.net,REJECT") {
		t.Fatal("failover still selected after deletion began", err)
	}
	state, err = c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	group := objects(state["failovers"])[0]
	if group["status"] != "deleting" || !reflect.DeepEqual(group["paths"], paths[1:]) {
		t.Fatal("pending path was not preserved")
	}
	backend.failServer = ""
	if _, err := c.DeleteFailover(ctx, "clash", "HA"); err != nil {
		t.Fatal(err)
	}
	state, err = c.Repository.State("clash")
	if err != nil || len(objects(state["failovers"])) != 0 || len(objects(state["serverChains"])) != 0 ||
		!reflect.DeepEqual(backend.writes, []string{"primary", "backup", "backup"}) {
		t.Fatal("completed path was replayed or metadata retained", err)
	}
}
