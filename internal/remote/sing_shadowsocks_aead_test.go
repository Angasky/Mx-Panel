package remote

import "testing"

func TestSingAEADManagedUserLifecycle(t *testing.T) {
	for _, template := range []string{"ss-aes-128-gcm", "ss-aes-256-gcm", "ss-chacha20-poly1305"} {
		t.Run(template, func(t *testing.T) {
			row := managedSSAEADFixture(t, template)
			native, err := legacyNativeInbound("sing-box", row)
			if err != nil {
				t.Fatal(err)
			}
			empty := native
			doc, err := planCoreStats("sing-box", Record{"inbounds": []any{native}})
			if err != nil {
				t.Fatal(err)
			}
			state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{"listen": coreStatsListen, "binary": "go-ssh-grpc", "users": []any{}}}
			bindings := []Record{}
			for i := 0; i < 2; i++ {
				user, err := NewUser(row)
				if err != nil {
					t.Fatal(err)
				}
				binding := bindingFor(t, row, user)
				binding["inboundId"] = 17
				next, rows, err := planCoreUserChange("sing-box", "add", state, doc, binding, false, user)
				if err != nil {
					t.Fatal(err)
				}
				stats, err := extendCoreStats("sing-box", doc, next, state.UserStats, binding)
				if err != nil {
					t.Fatal(err)
				}
				retry, _, err := planCoreUserChange("sing-box", "add", state, next, binding, true, user)
				if err != nil || !sameCoreInbound(next, retry) {
					t.Fatal("add retry changed user", err)
				}
				row, doc, state = rows[0], next, legacyCoreState{Inbounds: rows, UserStats: stats}
				bindings = append(bindings, binding)
			}
			groups, counts := coreCounterIndex("sing-box", doc, state.UserStats)
			if len(groups["mxioc-inbound-17"].emails) != 2 || counts[bindings[0]["userEmail"].(string)] != 1 {
				t.Fatal("user counters not isolated")
			}
			for _, op := range []string{"pause", "resume", "remove"} {
				if op == "resume" {
					bindings[0]["monthlyPaused"] = true
				}
				next, rows, err := planCoreUserChange("sing-box", op, state, doc, bindings[0], false)
				if err != nil {
					t.Fatal(op, err)
				}
				row, doc, state = rows[0], next, legacyCoreState{Inbounds: rows, UserStats: state.UserStats}
				if _, err := FindUser(row, bindings[1], false); err != nil {
					t.Fatal("peer changed", err)
				}
			}
			next, rows, err := planCoreUserChange("sing-box", "remove", state, doc, bindings[1], false)
			if err != nil {
				t.Fatal(err)
			}
			if !sameCoreInbound(empty, anyRecords(next["inbounds"])[0]) {
				t.Fatal("last removal did not restore private guard")
			}
			if nodes, err := InboundNodes(rows[0], Record{}); err != nil || len(nodes) != 0 {
				t.Fatal("guard exported", err)
			}
		})
	}
}
