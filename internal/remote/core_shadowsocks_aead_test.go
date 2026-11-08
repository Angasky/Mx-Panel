package remote

import (
	"encoding/json"
	"strings"
	"testing"
)

func managedSSAEADFixture(t *testing.T, template string) Record {
	t.Helper()
	row, err := buildStandaloneSSAEADTemplate(Record{"template": template})
	if err != nil {
		t.Fatal(err)
	}
	row["id"], row["tag"], row["goCreateKey"] = 17, "mxioc-inbound-17", "fixture"
	return row
}

func TestManagedSSAEADCredentialsAndOwnership(t *testing.T) {
	for _, template := range []string{"ss-aes-128-gcm", "ss-aes-256-gcm", "ss-chacha20-poly1305"} {
		t.Run(template, func(t *testing.T) {
			row := managedSSAEADFixture(t, template)
			if !coreProvisionInbound("xray", row) || !coreProvisionInbound("sing-box", row) || standaloneTemplateProtocol("sing-box", template) != "shadowsocks" {
				t.Fatal("template adapter eligibility incorrect")
			}
			if _, err := buildInboundTemplate(Record{"template": template}, ""); err == nil {
				t.Fatal("AEAD template exposed to external panels")
			}
			native, err := legacyNativeInbound("xray", row)
			if err != nil {
				t.Fatal(err)
			}
			doc, err := planCoreStats("xray", Record{"inbounds": []any{native}})
			if err != nil {
				t.Fatal(err)
			}
			state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{"listen": coreStatsListen, "binary": "/usr/local/bin/xray", "users": []any{}}}
			users, bindings := []Record{}, []Record{}
			for i := 0; i < 2; i++ {
				user, err := NewUser(row)
				if err != nil {
					t.Fatal(err)
				}
				binding := bindingFor(t, row, user)
				binding["inboundId"] = 17
				next, rows, err := planCoreUserChange("xray", "add", state, doc, binding, false, user)
				if err != nil {
					t.Fatal(err)
				}
				stats, err := extendCoreStats("xray", doc, next, state.UserStats, binding)
				if err != nil {
					t.Fatal(err)
				}
				retry, _, err := planCoreUserChange("xray", "add", state, next, binding, true, user)
				if err != nil || !sameCoreInbound(next, retry) {
					t.Fatal("add retry changed credential", err)
				}
				row, doc = rows[0], next
				state = legacyCoreState{Inbounds: rows, UserStats: stats}
				users, bindings = append(users, user), append(bindings, binding)
			}
			if users[0]["password"] == users[1]["password"] || users[0]["email"] == users[1]["email"] || users[0]["method"] != ssAEADTemplateMethod(template) {
				t.Fatal("per-user identity not isolated")
			}
			groups, _ := coreCounterIndex("xray", doc, state.UserStats)
			if len(groups["mxioc-inbound-17"].emails) != 2 {
				t.Fatal("users not enrolled for accounting")
			}
			settings := row["settings"].(Record)
			for _, binding := range bindings {
				next, rows, err := planCoreUserChange("xray", "remove", legacyCoreState{Inbounds: []Record{row}}, doc, binding, false)
				if err != nil {
					t.Fatal(err)
				}
				row, doc = rows[0], next
			}
			if !sameCoreInbound(native, anyRecords(doc["inbounds"])[0]) {
				t.Fatal("last user removal did not restore private guard")
			}
			if nodes, err := InboundNodes(row, Record{}); err != nil || len(nodes) != 0 {
				t.Fatal("empty guard exported", err)
			}
			// Root, user cipher and guard changes must all invalidate ownership.
			row["settings"].(Record)["clients"] = []any{users[0]}
			for name, mutate := range map[string]func(Record){
				"root":  func(r Record) { r["settings"].(Record)["password"] = users[1]["password"] },
				"guard": func(r Record) { r["goSSAEADGuard"] = users[1]["password"] },
				"owner": func(r Record) { r["goCreateKey"] = "other" },
				"shared": func(r Record) {
					s := r["settings"].(Record)
					s["clients"] = []any{users[0], Record{"email": "peer", "password": users[0]["password"], "method": users[0]["method"]}}
				},
				"cipher":     func(r Record) { anyRecords(r["settings"].(Record)["clients"])[0]["method"] = "other" },
				"reserved":   func(r Record) { anyRecords(r["settings"].(Record)["clients"])[0]["password"] = r["goSSAEADGuard"] },
				"mixed-mode": func(r Record) { r["goSS2022Guard"] = "invalid" },
			} {
				t.Run(name, func(t *testing.T) {
					raw, _ := json.Marshal(row)
					var changed Record
					if err := json.Unmarshal(raw, &changed); err != nil {
						t.Fatal(err)
					}
					mutate(changed)
					if _, err := FindUser(changed, bindings[0], false); err == nil {
						t.Fatal("changed identity accepted")
					}
				})
			}
			if native, err := legacyNativeInbound("sing-box", row); err != nil || len(anyRecords(native["users"])) != 1 || native["password"] != nil {
				t.Fatal("managed AEAD users not converted to sing-box", err)
			}
			nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
			if err != nil || len(nodes) != 1 {
				t.Fatal(err)
			}
			encoded, _ := json.Marshal(nodes)
			if nodes[0]["password"] != users[0]["password"] || strings.Contains(string(encoded), value(row["goSSAEADGuard"])) || strings.Contains(string(encoded), value(settings["password"])) {
				t.Fatal("guard or base password leaked")
			}
			delete(row, "goSSAEADGuard")
			if _, err := NewUser(row); err == nil {
				t.Fatal("legacy SS automatically enrolled")
			}
		})
	}
}
