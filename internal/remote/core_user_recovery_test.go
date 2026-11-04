package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCoreExpirySupersedesInterruptedResume(t *testing.T) {
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
	user := Record{"email": "alice", "id": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "enable": false}
	other := Record{"email": "bob", "id": "30403cc4-583b-426a-8424-ec98489977b2"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{user, other}}}
	binding := bindingFor(t, row, user)
	binding["inboundId"], binding["monthlyPaused"] = 17, true
	state, err := m.SealUser(Record{"inbounds": []any{row}, "otherLegacyField": "preserved"})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.updateCoreUserState(id, "", "", state, ""); err != nil {
		t.Fatal(err)
	}
	native, err := legacyNativeInbound("xray", row)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(Record{"inbounds": []any{native}})
	if err != nil {
		t.Fatal(err)
	}
	var writes int
	run := func(_ context.Context, script string, _ int) (string, error) {
		if strings.HasPrefix(script, "base64 < ") {
			return base64.StdEncoding.EncodeToString(raw), nil
		}
		const marker = "printf '%s' '"
		_, body, ok := strings.Cut(script, marker)
		if !ok {
			t.Fatal("missing candidate in script")
		}
		data, _, _ := strings.Cut(body, "'")
		var err error
		raw, err = base64.StdEncoding.DecodeString(data)
		if err != nil {
			t.Fatal(err)
		}
		writes++
		if writes == 1 {
			return "", errors.New("connection interrupted after file replacement")
		}
		return "MXIOC_CORE_APPLIED\n", nil
	}
	record, err := m.Record(id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.changeCoreUser(context.Background(), id, "xray", "resume", record, binding, run); err == nil {
		t.Fatal("interrupted resume unexpectedly succeeded")
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	record, err = m.Record(id)
	if err != nil || record["coreUserPending"] == nil {
		t.Fatal("interrupted operation did not persist")
	}
	original := raw
	raw = append(append([]byte{}, raw...), '\n')
	if _, err := m.changeCoreUser(context.Background(), id, "xray", "remove", record, binding, run); err == nil || writes != 1 {
		t.Fatal("unrecognized remote config was overwritten")
	}
	raw = original
	if _, err := m.changeCoreUser(context.Background(), id, "xray", "remove", record, binding, run); err != nil {
		t.Fatal(err)
	}
	record, err = m.Record(id)
	if err != nil || record["coreUserPending"] != nil || writes != 2 {
		t.Fatal("expiration did not finalize")
	}
	saved, err := m.OpenUser(value(record["coreState"]))
	if err != nil {
		t.Fatal(err)
	}
	config, err := object(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	savedRows := anyRecords(saved["inbounds"])
	actualRows := anyRecords(config["inbounds"])
	want, err := legacyNativeInbound("xray", savedRows[0])
	if err != nil || !sameCoreInbound(want, actualRows[0]) || saved["otherLegacyField"] != "preserved" {
		t.Fatal("remote and local state did not converge")
	}
	clients := anyRecords(actualRows[0]["settings"].(Record)["clients"])
	if len(clients) != 1 || clients[0]["email"] != "bob" {
		t.Fatal("expiration affected the wrong users")
	}
}
