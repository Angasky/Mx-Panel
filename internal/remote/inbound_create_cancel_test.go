package remote

import (
	"strings"
	"testing"
)

func TestCancelUnsentCreatesFencesRetriesButPreservesSentOperations(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	const profile = "clash"
	unsent, sent := strings.Repeat("a", 32), strings.Repeat("b", 32)
	key, _, err := createRequestIdentity(profile, Record{"operationId": sent})
	if err != nil {
		t.Fatal(err)
	}
	entry := Record{"scope": profile, "serverId": "server", "revision": "revision",
		"requestHash": "hash", "status": "sent", "sealedDesired": "fixture"}
	if err := m.saveCreate(key, entry); err != nil {
		t.Fatal(err)
	}
	if err := m.CancelUnsentCreates(profile, []string{unsent, sent}); err == nil {
		t.Fatal("a sent request must remain recoverable")
	}
	unsentKey, _, err := createRequestIdentity(profile, Record{"operationId": unsent})
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.loadCreate(unsentKey); err != nil || got != nil {
		t.Fatal("rejected cancellation must leave all requests intact")
	}
	if err := m.CancelUnsentCreates(profile, []string{unsent}); err != nil {
		t.Fatal(err)
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := m.loadCreate(unsentKey); err != nil || got["status"] != "canceled" {
		t.Fatal("cancellation did not survive restart", err)
	}
	if err := m.saveCreate(unsentKey, entry); err == nil {
		t.Fatal("canceled request could be sent")
	}
}
