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

func TestCancelUnsentCreatesFencesStandaloneWrites(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := serverPayload()
	payload["installType"] = "xray"
	delete(payload, "panelAddress")
	server, err := m.Save(payload)
	if err != nil {
		t.Fatal(err)
	}
	id := value(server["id"])
	const profile = "clash"
	keyFor := func(operation string) string {
		key, _, err := createRequestIdentity(profile, Record{"operationId": operation})
		if err != nil {
			t.Fatal(err)
		}
		return key
	}
	seal := func(doc Record) string {
		token, err := m.SealUser(doc)
		if err != nil {
			t.Fatal(err)
		}
		return token
	}
	canceled, sent, untouched := strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 32)
	if err := m.CancelUnsentCreates(profile, []string{canceled}); err != nil {
		t.Fatal(err)
	}
	canceledKey := keyFor(canceled)
	if err := m.reserveCoreCreate(id, canceledKey, "", seal(Record{"operation": coreInboundCreate, "key": canceledKey})); err == nil {
		t.Fatal("canceled standalone request reserved a remote write")
	}
	sentKey := keyFor(sent)
	intent := seal(Record{"operation": coreInboundCreate, "key": sentKey})
	if err := m.reserveCoreCreate(id, sentKey, "", intent); err != nil {
		t.Fatal(err)
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.CancelUnsentCreates(profile, []string{untouched, sent}); err == nil {
		t.Fatal("a pending standalone request must remain recoverable")
	}
	if got, err := m.loadCreate(keyFor(untouched)); err != nil || got != nil {
		t.Fatal("rejected cancellation fenced another path", err)
	}
	state := seal(Record{"inbounds": []any{Record{"goCreateKey": sentKey}}})
	if err := m.updateCoreUserState(id, "", intent, state, ""); err != nil {
		t.Fatal(err)
	}
	if err := m.CancelUnsentCreates(profile, []string{sent}); err == nil {
		t.Fatal("confirmed standalone request cannot be treated as unsent")
	}
}
