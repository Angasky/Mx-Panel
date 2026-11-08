package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestBindingCleanupAndGenerationGuard(t *testing.T) {
	r, primary, _ := fixture(t)
	yaml, _ := os.ReadFile(primary)
	err := r.UpdateState("clash", func(p Document) error {
		p["traffic"] = Document{"upload": 123}
		bindings := []any{}
		for _, status := range []string{"revoked", "missing", "detached", "identity_changed", "active", "provisioning", "unknown"} {
			bindings = append(bindings, Document{"status": status, "serverId": "server", "operationId": status, "error": status})
		}
		p["remoteNodes"] = bindings
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	p, _ := r.State("clash")
	b := rows(p, "remoteNodes")[4].(Document)
	token := BindingToken("clash", b)
	b["up"], b["status"] = 999, "missing"
	if BindingToken("clash", b) != token || BindingToken("other", b) == token {
		t.Fatal("token scope or sample stability")
	}
	if _, err = r.CleanupBindings("clash", false); err == nil {
		t.Fatal("missing confirmation")
	}
	if n, err := r.CleanupBindings("clash", true); err != nil || n != 4 {
		t.Fatal(n, err)
	}
	if err = r.RemoveBinding("clash", 0, BindingToken("clash", Document{"operationId": "wrong"}), true); err == nil {
		t.Fatal("accepted replaced record")
	}
	if err = r.RemoveBinding("clash", 4, token, true); err == nil {
		t.Fatal("accepted stale index")
	}
	p, _ = r.State("clash")
	info, err := TrafficInfo(p, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	first := info["bindings"].([]any)[0].(Document)
	if first["recordToken"] != token {
		t.Fatal("public token mismatch")
	}
	if err = r.RemoveBinding("clash", 0, token, false); err == nil {
		t.Fatal("unconfirmed removal")
	}
	if err = r.RemoveBinding("clash", 0, token, true); err != nil {
		t.Fatal(err)
	}
	p, _ = r.State("clash")
	if len(rows(p, "remoteNodes")) != 2 || fmt.Sprint(p["traffic"].(Document)["upload"]) != "123" {
		t.Fatal("usage or unrelated rows changed")
	}
	after, _ := os.ReadFile(primary)
	if string(after) != string(yaml) {
		t.Fatal("cleanup changed subscription YAML")
	}
}

func TestDetachServerRollbackAndAllProfiles(t *testing.T) {
	r, primary, _ := fixture(t)
	r.mu.Lock()
	index, _ := r.index()
	p := index["profiles"].([]any)[0].(Document)
	p["remoteNodes"] = []any{Document{"serverId": "target", "status": "active"}, Document{"serverId": "other", "status": "active"}}
	index["profiles"] = append(index["profiles"].([]any), Document{"id": "second", "remoteNodes": []any{Document{"serverId": "target", "status": "provisioning", "pendingUser": "encrypted"}}})
	err := r.writeIndex(index)
	r.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(r.Root, "profiles.json")
	before, _ := os.ReadFile(path)
	yaml, _ := os.ReadFile(primary)
	called := false
	if _, err = r.DetachServer("target", false, func() error { called = true; return nil }); err == nil || called {
		t.Fatal("unconfirmed detach committed")
	}
	failure := errors.New("registry disk failure")
	if _, err = r.DetachServer("target", true, func() error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed registry commit did not roll back exactly")
	}
	result, err := r.DetachServer("target", true, func() error { called = true; return nil })
	if err != nil || !called || result["detachedBindings"] != 2 {
		t.Fatal(result, err)
	}
	p, _ = r.State("clash")
	second, _ := r.State("second")
	if rows(p, "remoteNodes")[0].(Document)["status"] != "detached" || rows(p, "remoteNodes")[1].(Document)["status"] != "active" || rows(second, "remoteNodes")[0].(Document)["status"] != "detached" {
		t.Fatal("wrong detach scope")
	}
	after, _ = os.ReadFile(primary)
	if string(yaml) != string(after) {
		t.Fatal("remote detachment edited node export")
	}
}

func TestBulkHistoryCleanupPreservesRecoveryRecords(t *testing.T) {
	r, primary, _ := fixture(t)
	before, err := os.ReadFile(primary)
	if err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateState("clash", func(p Document) error {
		p["traffic"] = Document{"upload": 123}
		p["remoteNodes"] = []any{
			Document{"status": "missing", "localCleanupPending": true, "operationId": "local", "importedNodes": []any{Document{"name": "owned", "identity": "proof"}}},
			Document{"status": "revoked", "inboundDeletePending": Document{"expected": "remote-proof"}, "operationId": "remote"},
			Document{"status": "missing", "operationId": "done"},
			Document{"status": "active", "operationId": "active"},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if removed, err := r.CleanupBindings("clash", true); err != nil || removed != 1 {
		t.Fatal(removed, err)
	}
	reopened := &Repository{Root: r.Root}
	p, err := reopened.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	bindings := rows(p, "remoteNodes")
	if len(bindings) != 3 || bindings[0].(Document)["localCleanupPending"] != true || bindings[1].(Document)["inboundDeletePending"] == nil {
		t.Fatal("recovery evidence removed")
	}
	if fmt.Sprint(p["traffic"].(Document)["upload"]) != "123" {
		t.Fatal("history cleanup changed billing")
	}
	after, _ := os.ReadFile(primary)
	if string(before) != string(after) {
		t.Fatal("history cleanup rewrote subscription")
	}
	if err := reopened.UpdateState("clash", func(p Document) error {
		delete(rows(p, "remoteNodes")[0].(Document), "localCleanupPending")
		delete(rows(p, "remoteNodes")[1].(Document), "inboundDeletePending")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if removed, err := reopened.CleanupBindings("clash", true); err != nil || removed != 2 {
		t.Fatal("completed recovery records not cleanable", removed, err)
	}
}
