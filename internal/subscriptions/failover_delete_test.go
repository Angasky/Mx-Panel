package subscriptions

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

type failoverDeleteBackend struct {
	*fakeBackend
	failServer string
	writes     []string
	canceled   []string
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

func (b *failoverDeleteBackend) CancelUnsentCreates(_ string, requests []string) error {
	b.canceled = append(b.canceled, requests...)
	return nil
}

func TestCancelFailoverDraftWithoutRemotePaths(t *testing.T) {
	testCancelFailoverDraft(t, false)
}

func TestCancelFailoverDraftCleansOnlyCompletedPaths(t *testing.T) {
	testCancelFailoverDraft(t, true)
}

func testCancelFailoverDraft(t *testing.T, completed bool) {
	t.Helper()
	c, base, _ := controllerFixture(t)
	backend := &failoverDeleteBackend{fakeBackend: base}
	c.Backend = backend
	const name = "draft"
	op := strings.Repeat("a", 32)
	ids := []string{config.FailoverPathRequest(op, 0), config.FailoverPathRequest(op, 1)}
	paths := []any{"draft / 1", "draft / 2"}
	var writes []string
	if completed {
		if _, err := c.Batch(context.Background(), "clash", "primary", []int{1}); err != nil {
			t.Fatal(err)
		}
		names := stateBinding(t, c)["importedNames"].([]any)
		paths[0] = names[0]
		writes = []string{"primary"}
	}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		if completed {
			binding := objects(p["remoteNodes"])[0]
			binding["chainRequest"] = ids[0]
			p["serverChains"] = []any{Record{"name": paths[0], "entry": "entry1", "exit": "exit",
				"requestId": ids[0], "serverId": "primary", "inboundId": 1}}
		}
		p["failoverDrafts"] = []any{Record{"name": name, "status": "creating", "requestId": op,
			"paths": paths, "entries": []any{"entry1", "entry2"},
			"pathRequests": []any{ids[0], ids[1]}, "exit": "exit"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteFailover(context.Background(), "clash", name); err != nil {
		t.Fatal(err)
	}
	state, err := c.Repository.State("clash")
	if completed {
		ids = ids[1:]
	}
	if err != nil || len(objects(state["failovers"])) != 0 || len(objects(state["failoverDrafts"])) != 0 ||
		len(objects(state["serverChains"])) != 0 || !reflect.DeepEqual(backend.writes, writes) || !reflect.DeepEqual(backend.canceled, ids) {
		t.Fatal("draft was not canceled safely", err)
	}
}

type pendingFailoverBackend struct {
	*failoverDeleteBackend
	fail  bool
	calls int
}

func (b *pendingFailoverBackend) CancelPendingCreates(ctx context.Context, profile string, requests []string, guard func(string, string, int, Record) error) (Record, error) {
	b.calls++
	if b.fail {
		return nil, errors.New("late result not yet visible")
	}
	for _, request := range requests {
		if request == config.FailoverPathRequest(strings.Repeat("d", 32), 0) {
			if err := guard(request, "primary", 1, clone(b.rows[0])); err != nil {
				return nil, err
			}
			b.rows = b.rows[1:]
		}
	}
	return Record{"canceled": true}, nil
}
func TestFailoverCancellationIsDurableAndCleansPartialUser(t *testing.T) {
	c, base, root := controllerFixture(t)
	b := &pendingFailoverBackend{failoverDeleteBackend: &failoverDeleteBackend{fakeBackend: base}, fail: true}
	c.Backend = b
	if _, err := c.Batch(context.Background(), "clash", "primary", []int{1}); err != nil {
		t.Fatal(err)
	}
	op := strings.Repeat("d", 32)
	requests := []any{config.FailoverPathRequest(op, 0), config.FailoverPathRequest(op, 1)}
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		objects(p["remoteNodes"])[0]["chainRequest"] = requests[0]
		p["failoverDrafts"] = []any{Record{"name": "HA", "status": "creating", "requestId": op, "requestHash": "hash", "operationId": op, "paths": []any{"HA / 1", "HA / 2"}, "entries": []any{"first", "second"}, "pathRequests": requests, "exit": "exit"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DeleteFailover(context.Background(), "clash", "HA"); err == nil {
		t.Fatal("pending cancellation reported complete")
	}
	c.Repository = &config.Repository{Root: root}
	state, _ := c.Repository.State("clash")
	draft := objects(state["failoverDrafts"])[0]
	if draft["cancelRequested"] != true {
		t.Fatal("lost durable cancellation")
	}
	if err := c.Repository.BeginFailover("clash", draft); err == nil {
		t.Fatal("canceled draft restarted creation")
	}
	b.fail = false
	if _, err := c.DeleteFailover(context.Background(), "clash", "HA"); err != nil {
		t.Fatal(err)
	}
	state, _ = c.Repository.State("clash")
	if len(objects(state["failoverDrafts"])) != 0 || len(objects(state["failovers"])) != 0 || stateBinding(t, c)["status"] != "missing" {
		t.Fatal("cancel cleanup incomplete", state)
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("partially imported node retained")
	}
	if b.adds != 1 {
		t.Fatal("cancellation created another user")
	}
}
