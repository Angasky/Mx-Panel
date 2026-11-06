package remote

import (
	"encoding/json"
	"strings"
	"testing"
)

func managedSS2022Fixture(t *testing.T, template string) Record {
	t.Helper()
	row, err := buildStandaloneSS2022Template(Record{"template": template})
	if err != nil {
		t.Fatal(err)
	}
	row["goCreateKey"], row["id"], row["tag"] = "fixture", 17, "mxioc-inbound-17"
	return row
}

func TestManagedSS2022IndependentUsersAndEmptyGuard(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		for _, template := range []string{"ss2022-aes-128", "ss2022-aes-256"} {
			t.Run(kind+"/"+template, func(t *testing.T) {
				row := managedSS2022Fixture(t, template)
				native, err := legacyNativeInbound(kind, row)
				if err != nil {
					t.Fatal(err)
				}
				doc, err := planCoreStats(kind, Record{"inbounds": []any{native}})
				if err != nil {
					t.Fatal(err)
				}
				state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{"listen": coreStatsListen, "binary": "/usr/local/bin/xray", "users": []any{}}}
				var users, bindings []Record
				for i := 0; i < 2; i++ {
					user, err := NewUser(state.Inbounds[0])
					if err != nil {
						t.Fatal(err)
					}
					binding := bindingFor(t, state.Inbounds[0], user)
					binding["inboundId"] = 17
					next, rows, err := planCoreUserChange(kind, "add", state, doc, binding, false, user)
					if err != nil {
						t.Fatal(err)
					}
					stats, err := extendCoreStats(kind, doc, next, state.UserStats, binding)
					if err != nil {
						t.Fatal(err)
					}
					state, doc = legacyCoreState{Inbounds: rows, UserStats: stats}, next
					users, bindings = append(users, user), append(bindings, binding)
				}
				if users[0]["password"] == users[1]["password"] || users[0]["email"] == users[1]["email"] || users[0]["id"] != nil {
					t.Fatal("SS2022 credentials reused or wrong credential type")
				}
				groups, counts := coreCounterIndex(kind, doc, state.UserStats)
				if len(groups["mxioc-inbound-17"].emails) != 2 || counts[ss2022GuardEmail] != 0 {
					t.Fatal("independent counters not registered")
				}
				for _, binding := range bindings {
					next, rows, err := planCoreUserChange(kind, "remove", state, doc, binding, false)
					if err != nil {
						t.Fatal(err)
					}
					state.Inbounds, doc = rows, next
				}
				groups, _ = coreCounterIndex(kind, doc, state.UserStats)
				if len(groups["mxioc-inbound-17"].emails) != 0 {
					t.Fatal("guard counted as subscription traffic")
				}
				nodes, err := InboundNodes(state.Inbounds[0], Record{})
				if err != nil || len(nodes) != 0 {
					t.Fatal("empty guard exported", err)
				}
				original, _ := legacyNativeInbound(kind, row)
				if !sameCoreInbound(original, anyRecords(doc["inbounds"])[0]) {
					t.Fatal("empty state did not restore original guard")
				}
			})
		}
	}
}

func TestManagedSS2022IdentityAndCredentialGuards(t *testing.T) {
	row := managedSS2022Fixture(t, "ss2022-aes-128")
	for _, template := range []string{"ss2022-aes-128", "ss2022-aes-256"} {
		if standaloneTemplateProtocol("sing-box", template) != "shadowsocks" {
			t.Fatal("sing-box SS2022 template missing")
		}
		if _, err := buildInboundTemplate(Record{"template": template}, ""); err == nil {
			t.Fatal("standalone SS2022 template accepted for an external panel")
		}
	}
	if !coreProvisionInbound("sing-box", row) {
		t.Fatal("guarded sing-box SS2022 provisioning missing")
	}
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	row["settings"].(Record)["clients"] = []any{user}
	binding := bindingFor(t, row, user)
	for name, change := range map[string]func(Record){
		"root":          func(r Record) { r["settings"].(Record)["password"] = user["password"] },
		"guard":         func(r Record) { r["goSS2022Guard"] = user["password"] },
		"method":        func(r Record) { r["settings"].(Record)["method"] = "2022-blake3-aes-256-gcm" },
		"owner":         func(r Record) { r["goCreateKey"] = "different" },
		"no-owner":      func(r Record) { delete(r, "goCreateKey") },
		"reserved-name": func(r Record) { anyRecords(r["settings"].(Record)["clients"])[0]["email"] = ss2022GuardEmail },
		"shared-password": func(r Record) {
			s := r["settings"].(Record)
			s["clients"] = append(s["clients"].([]any), Record{"email": "peer", "password": user["password"]})
		},
		"extension": func(r Record) { r["settings"].(Record)["users"] = []any{} },
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := json.Marshal(row)
			var changed Record
			if err := json.Unmarshal(raw, &changed); err != nil {
				t.Fatal(err)
			}
			change(changed)
			if _, err := FindUser(changed, binding, false); err == nil {
				t.Fatal("changed identity accepted")
			}
		})
	}
	for _, kind := range []string{"xray", "sing-box"} {
		legacy := ss2022Fixture("2022-blake3-aes-128-gcm")
		legacy["settings"].(Record)["clients"] = []any{}
		if _, err := legacyNativeInbound(kind, legacy); err == nil {
			t.Fatal("unguarded empty configuration accepted")
		}
		if coreProvisionInbound(kind, legacy) {
			t.Fatal("legacy SS2022 enrolled without guard")
		}
	}
	if _, err := NewUser(ss2022Fixture("2022-blake3-aes-128-gcm")); err == nil {
		t.Fatal("legacy SS2022 users enabled")
	}
	raw, _ := json.Marshal(row)
	nodes, err := InboundNodes(row, Record{"host": "example.com"})
	if err != nil || len(nodes) != 1 {
		t.Fatal(err)
	}
	exported, _ := json.Marshal(nodes)
	if strings.Contains(string(exported), value(row["goSS2022Guard"])) {
		t.Fatal("private guard leaked")
	}
	after, _ := json.Marshal(row)
	if string(raw) != string(after) {
		t.Fatal("export mutated guard or users")
	}
}
