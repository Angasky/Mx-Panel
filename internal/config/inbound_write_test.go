package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func TestInboundEditProtectsOwnedUserAndPendingCreation(t *testing.T) {
	r, _, _ := fixture(t)
	user := Document{"id": "own-id", "email": "owned", "flow": "", "enable": true}
	old := Document{"id": 1, "tag": "inbound-24001", "port": 24001, "protocol": "vless", "streamSettings": Document{}, "settings": Document{"clients": []any{user}}}
	endpoint, _ := remote.EndpointIdentity(old)
	hash, _ := remote.UserIdentity(user)
	binding := Document{"serverId": "s", "inboundId": 1, "scope": "user", "status": "active", "identityHash": endpoint, "userHash": hash, "userEmail": "owned"}
	if err := r.UpdateState("clash", func(p Document) error { p["remoteNodes"] = []any{binding}; return nil }); err != nil {
		t.Fatal(err)
	}
	next := Document{}
	for k, v := range old {
		next[k] = v
	}
	next["remark"] = "new"
	if err := r.GuardInboundEdit("s", 1, old, next); err != nil {
		t.Fatal(err)
	}
	next["streamSettings"] = Document{"network": "ws", "wsSettings": Document{"path": "/", "headers": Document{"Host": "cdn.example.com"}}}
	if err := r.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("bound endpoint Host changed")
	}
	next["streamSettings"] = old["streamSettings"]
	next["settings"] = Document{"clients": []any{}}
	if err := r.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("owned user removed")
	}
	next["settings"] = old["settings"]
	next["port"] = 24002
	if err := r.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("bound endpoint changed")
	}
	if err := r.UpdateState("clash", func(p Document) error { rows(p, "remoteNodes")[0].(Document)["status"] = "provisioning"; return nil }); err != nil {
		t.Fatal(err)
	}
	if err := r.GuardInboundEdit("s", 1, old, old); err == nil {
		t.Fatal("pending creation overwritten")
	}
}

func TestInboundDeleteIntentDurabilityAndTargetedCleanup(t *testing.T) {
	r, _, _ := managedFixture(t)
	if err := r.UpdateState("clash", func(p Document) error {
		p["remoteNodes"] = append(rows(p, "remoteNodes"), Document{"serverId": "s", "inboundId": 2, "status": "active", "name": "other"})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	observed, _ := r.BindingSnapshot("s")
	if err := r.BeginInboundDelete("s", 1, strings.Repeat("a", 64), nil, observed); err != nil {
		t.Fatal(err)
	}
	reopened := &Repository{Root: r.Root}
	if err := reopened.CheckInboundAvailable("s", 1); err == nil {
		t.Fatal("delete journal lost across restart")
	}
	if err := reopened.CheckInboundAvailable("s", 2); err != nil {
		t.Fatal("unrelated inbound blocked", err)
	}
	snapshot, _ := reopened.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("deleted local node before remote confirmation")
	}
	n, err := reopened.ConfirmInboundDeleted("s", 1, observed)
	if err != nil || n != 1 {
		t.Fatal(n, err)
	}
	p, _ := reopened.State("clash")
	bindings := rows(p, "remoteNodes")
	if bindings[0].(Document)["status"] != "missing" || bindings[1].(Document)["status"] != "active" {
		t.Fatal(bindings)
	}
	if err = reopened.CheckInboundAvailable("s", 1); err != nil {
		t.Fatal("journal not resolved", err)
	}
}

func TestInboundDeleteCleanupFailureAndStaleGeneration(t *testing.T) {
	r, primary, _ := managedFixture(t)
	observed, _ := r.BindingSnapshot("s")
	if err := r.BeginInboundDelete("s", 1, strings.Repeat("a", 64), nil, observed); err != nil {
		t.Fatal(err)
	}
	index, _ := r.index()
	p, _ := stateRecord(index, "clash")
	p["files"] = []any{primary, filepath.Join(r.Root, "absent", "mirror.yaml")}
	if err := r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConfirmInboundDeleted("s", 1, observed); err == nil {
		t.Fatal("mirror failure ignored")
	}
	p, _ = r.State("clash")
	b := rows(p, "remoteNodes")[0].(Document)
	if b["status"] != "missing" || b["localCleanupPending"] != true {
		t.Fatal("cleanup failure lost", b)
	}
	if err := os.Mkdir(filepath.Join(r.Root, "absent"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ConfirmInboundDeleted("s", 1, observed); err != nil {
		t.Fatal("cleanup retry failed", err)
	}
	p, _ = r.State("clash")
	if rows(p, "remoteNodes")[0].(Document)["localCleanupPending"] != nil {
		t.Fatal("pending marker retained")
	}
	r, _, _ = managedFixture(t)
	observed, _ = r.BindingSnapshot("s")
	if err := r.UpdateState("clash", func(p Document) error {
		rows(p, "remoteNodes")[0].(Document)["operationId"] = "new-generation"
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if n, err := r.ConfirmInboundDeleted("s", 1, observed); err != nil || n != 0 {
		t.Fatal("stale deletion removed newer binding", n, err)
	}
}

func TestInboundEditChecksBindingsInOtherProfilesAndLegacyIdentity(t *testing.T) {
	r, _, _ := fixture(t)
	old := Document{"id": 1, "port": 24001, "protocol": "vless", "settings": Document{"clients": []any{Document{"id": "legacy-id"}}}, "streamSettings": Document{}}
	hash, _ := remote.LegacyInboundIdentity(old)
	index, _ := r.index()
	index["profiles"] = append(rows(index, "profiles"), Document{"id": "other", "name": "other", "remoteNodes": []any{Document{"serverId": "s", "inboundId": 1, "status": "active", "identityHash": hash}}})
	if err := r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	next := Document{}
	for k, v := range old {
		next[k] = v
	}
	next["enable"] = false
	if err := r.GuardInboundEdit("s", 1, old, next); err != nil {
		t.Fatal(err)
	}
	next["settings"] = Document{"clients": []any{}}
	if err := r.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("ignored other profile's legacy binding")
	}
	old["tag"], next["tag"] = "mxioc-inbound-1", "mxioc-inbound-1"
	next["settings"] = old["settings"]
	next["streamSettings"] = Document{"network": "ws", "wsSettings": Document{"path": "/changed"}}
	if err := r.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("accepted transport change while another profile still uses the old endpoint")
	}
	next["streamSettings"] = old["streamSettings"]
	next["remark"] = "renamed"
	if err := r.GuardInboundEdit("s", 1, old, next); err != nil {
		t.Fatal("name-only change should preserve the binding", err)
	}
}
