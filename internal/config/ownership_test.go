package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func pendingBinding() Document {
	return Document{"scope": "user", "status": "provisioning", "serverId": "server", "inboundId": 1, "operationId": "intent", "identityHash": "endpoint", "userEmail": "owned", "userHash": "user", "pendingUser": "encrypted"}
}
func TestConcurrentOwnershipAndImportRecovery(t *testing.T) {
	r, primary, mirror := fixture(t)
	var group sync.WaitGroup
	for i := 0; i < 8; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := r.BeginOwnership("clash", pendingBinding()); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	p, err := r.State("clash")
	if err != nil || len(rows(p, "remoteNodes")) != 1 {
		t.Fatal("duplicate ownership", err)
	}
	if err = r.GuardServerUpdate("server", Document{"host": "new"}, Document{"host": "old"}); err == nil {
		t.Fatal("changed pending server identity")
	}
	// A mirror write failure must leave the encrypted pending intent intact.
	if err = os.Remove(mirror); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(mirror, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err = r.ImportOwnedNode("clash", "intent", node("shared")); err == nil {
		t.Fatal("mirror failure hidden")
	}
	p, _ = r.State("clash")
	if rows(p, "remoteNodes")[0].(Document)["status"] != "provisioning" {
		t.Fatal("premature completion")
	}
	if err = os.Remove(mirror); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(primary)
	if err = os.WriteFile(mirror, data, 0600); err != nil {
		t.Fatal(err)
	}
	result, err := r.ImportOwnedNode("clash", "intent", node("shared"))
	if err != nil || result["added"] != 1 {
		t.Fatal(result, err)
	}
	// Emulate termination between YAML rename and the JSON completion marker.
	if err = r.UpdateState("clash", func(p Document) error {
		b := rows(p, "remoteNodes")[0].(Document)
		b["status"] = "provisioning"
		b["pendingUser"] = "encrypted"
		delete(b, "importedNames")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	r = &Repository{Root: r.Root}
	result, err = r.ImportOwnedNode("clash", "intent", node("shared"))
	if err != nil || result["existing"] != 1 {
		t.Fatal("recovery duplicated YAML node", result, err)
	}
	snapshot, err := r.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("saved node missing")
	}
	p, _ = r.State("clash")
	if _, exists := rows(p, "remoteNodes")[0].(Document)["pendingUser"]; exists {
		t.Fatal("pending credential retained after completion")
	}
}
func TestMalformedOwnershipFailsClosed(t *testing.T) {
	r, _, _ := fixture(t)
	for _, bad := range []any{"not-list", []any{"not-object"}} {
		index := Document{"profiles": []any{Document{"id": "clash", "remoteNodes": bad}}}
		raw, _ := json.Marshal(index)
		if err := os.WriteFile(filepath.Join(r.Root, "profiles.json"), raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.State("clash"); err == nil {
			t.Fatal("invalid ownership ignored")
		}
	}
}
