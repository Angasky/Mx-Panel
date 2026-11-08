package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// Exercises the real adapter journal and disk state, replacing only SSH and
// counters. Existing-user enrollment differs from importing a brand-new user.
func TestExistingUserEnrollmentRecoversNativeJournal(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			m, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			payload := serverPayload()
			payload["installType"] = kind
			delete(payload, "panelAddress")
			server, err := m.Save(payload)
			if err != nil {
				t.Fatal(err)
			}
			id := value(server["id"])
			user := Record{"id": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "email": "legacy-enrollment"}
			row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless", "settings": Record{"clients": []any{user}}}
			binding := bindingFor(t, row, user)
			binding["inboundId"] = 17
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := planCoreStats(kind, Record{"inbounds": []any{native}, "outbounds": []any{}})
			if err != nil {
				t.Fatal(err)
			}
			stats := Record{"listen": coreStatsListen, "binary": "/usr/local/bin/xray", "users": []any{}}
			if kind == "sing-box" {
				stats["binary"] = "go-ssh-grpc"
			}
			state, err := m.SealUser(Record{"inbounds": []any{row}, "userStats": stats, "preserve": "legacy metadata"})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.updateCoreUserState(id, "", "", state, ""); err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			run := func(_ context.Context, script string, _ int) (string, error) {
				if strings.HasPrefix(script, "base64 < ") {
					return base64.StdEncoding.EncodeToString(raw), nil
				}
				if strings.HasPrefix(script, "/usr/local/bin/xray api") {
					return "{}", nil
				}
				_, tail, ok := strings.Cut(script, "printf '%s' '")
				if !ok {
					t.Fatal("unexpected script")
				}
				encoded, _, _ := strings.Cut(tail, "'")
				candidate, err := base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				raw = candidate
				writes++
				if writes == 1 {
					return "", errors.New("SSH disconnected after replacement")
				}
				return "MXIOC_CORE_APPLIED", nil
			}
			ctx := context.WithValue(context.Background(), coreStatsQueryKey{}, coreStatsQuery(func(context.Context, string) (string, error) { return "{}", nil }))
			enroll := func() (Record, error) {
				record, err := m.Record(id)
				if err != nil {
					return nil, err
				}
				return m.changeCoreUser(ctx, id, kind, "add", record, binding, run, nil)
			}
			result, err := enroll()
			if kind == "sing-box" {
				if err == nil || writes != 1 {
					t.Fatal("interrupted registration reported success", err, writes)
				}
				m, err = Open(root)
				if err != nil {
					t.Fatal(err)
				}
				record, err := m.Record(id)
				if err != nil || record["coreUserPending"] == nil {
					t.Fatal("journal not durable", err)
				}
				// A byte-level config drift is not ours and cannot be overwritten on retry.
				exact := append([]byte{}, raw...)
				raw = append(raw, '\n')
				if _, err := enroll(); err == nil || writes != 1 {
					t.Fatal("foreign configuration overwritten")
				}
				raw = exact
				result, err = enroll()
			}
			if err != nil {
				t.Fatal("registration retry failed", err)
			}
			reading, _ := result["reading"].(Record)
			if reading["source"] != "authenticated-client" {
				t.Fatal("registered counters not confirmed")
			}
			before := writes
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := enroll(); err != nil || writes != before {
				t.Fatal("completed enrollment rewrote remote config", err)
			}
			record, err := m.Record(id)
			if err != nil || record["coreUserPending"] != nil {
				t.Fatal("journal not finalized", err)
			}
			saved, err := m.OpenUser(value(record["coreState"]))
			if err != nil {
				t.Fatal(err)
			}
			rows := anyRecords(saved["inbounds"])
			clients := anyRecords(rows[0]["settings"].(Record)["clients"])
			if len(clients) != 1 || clients[0]["id"] != user["id"] || saved["preserve"] != "legacy metadata" {
				t.Fatal("enrollment changed credentials or unrelated metadata")
			}
			users := anyStrings(saved["userStats"].(Record)["users"])
			if len(users) != 1 || users[0] != user["email"] {
				t.Fatal("counter enrollment duplicated")
			}
		})
	}
}
