package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

func managedFixture(t *testing.T) (*Repository, string, string) {
	r, p, m := fixture(t)
	n := node("owned")
	if err := r.Mutate("clash", func(d Document) error {
		d["proxies"] = []any{n}
		d["proxy-groups"] = []any{Document{"name": "Proxy", "type": "select", "proxies": []any{"owned"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateState("clash", func(p Document) error {
		p["remoteNodes"] = []any{Document{"serverId": "s", "inboundId": 1, "status": "active", "scope": "user", "importedNodes": []any{Document{"name": "owned", "identity": managednodes.Identity(n)}}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return r, p, m
}
func TestManagedCleanupRemovesReferencesRepairsMirrorsAndKeepsHistory(t *testing.T) {
	r, p, m := managedFixture(t)
	observed, _ := r.BindingSnapshot("s")
	if _, err := r.ReconcileInventory("clash", "s", map[int]bool{}, observed); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := r.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("orphan retained")
	}
	group := snapshot["groups"].([]any)[0].(Document)["config"].(Document)
	if group["proxies"].([]any)[0] != "DIRECT" {
		t.Fatal("empty group left")
	}
	state, _ := r.State("clash")
	if state["remoteNodes"].([]any)[0].(Document)["status"] != "missing" {
		t.Fatal("lost absence/history")
	}
	if err := os.WriteFile(m, []byte("stale mirror"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.CleanupMissing("clash"); err != nil {
		t.Fatal(err)
	}
	a, _ := os.ReadFile(p)
	b, _ := os.ReadFile(m)
	if !bytes.Equal(a, b) {
		t.Fatal("cleanup retry did not repair mirror")
	}
}
func TestManagedCleanupRollbackAndFailoverReference(t *testing.T) {
	r, primary, _ := managedFixture(t)
	if err := r.UpdateState("clash", func(p Document) error { p["failovers"] = []any{Document{"entries": []any{"owned"}}}; return nil }); err != nil {
		t.Fatal(err)
	}
	observed, _ := r.BindingSnapshot("s")
	if _, err := r.ReconcileInventory("clash", "s", map[int]bool{}, observed); err != nil {
		t.Fatal("failover guard kept known-dead node", err)
	}
	r, primary, _ = managedFixture(t)
	raw, _ := os.ReadFile(primary)
	index, _ := r.index()
	record, _ := stateRecord(index, "clash")
	record["files"] = []any{primary, filepath.Join(r.Root, "absent", "mirror.yaml")}
	if err := r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	observed, _ = r.BindingSnapshot("s")
	if _, err := r.ReconcileInventory("clash", "s", map[int]bool{}, observed); err == nil {
		t.Fatal("mirror failure ignored")
	}
	after, _ := os.ReadFile(primary)
	if !bytes.Equal(raw, after) {
		t.Fatal("cleanup failed to roll back")
	}
	state, _ := r.State("clash")
	binding := state["remoteNodes"].([]any)[0].(Document)
	if binding["status"] != "missing" || binding["localNodesRemovedAt"] != nil {
		t.Fatal("failed cleanup not retryable")
	}
}
func TestImportTargetsReadLocalProofsAndIgnorePending(t *testing.T) {
	r, _, _ := managedFixture(t)
	targets, err := r.ImportTargets("s", []int{1, 2})
	if err != nil || len(targets[0]["importedInboundIds"].([]int)) != 1 {
		t.Fatal(targets, err)
	}
	if err := r.UpdateState("clash", func(p Document) error { p["remoteNodes"].([]any)[0].(Document)["status"] = "provisioning"; return nil }); err != nil {
		t.Fatal(err)
	}
	targets, _ = r.ImportTargets("s", []int{1})
	if len(targets[0]["importedInboundIds"].([]int)) != 0 {
		t.Fatal("pending identity hidden")
	}
	wire, _ := json.Marshal(targets)
	if bytes.Contains(wire, []byte("secret")) {
		t.Fatal("credentials leaked")
	}
}
