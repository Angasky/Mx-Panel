package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"
)

func TestReadCoreUserCountsOnlyBoundIdentity(t *testing.T) {
	user := Record{"id": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "email": "alice"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{user}}}
	binding := bindingFor(t, row, user)
	binding["inboundId"] = 17
	native, err := legacyNativeInbound("xray", row)
	if err != nil {
		t.Fatal(err)
	}
	const listen = "127.0.0.1:10085"
	state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{
		"listen": listen, "binary": "/usr/local/bin/xray", "users": []any{"alice"},
	}}
	doc := Record{
		"api":      Record{"tag": "mxioc-user-stats", "listen": listen, "services": []any{"StatsService"}},
		"inbounds": []any{native}, "stats": Record{},
		"policy": Record{"levels": Record{"0": Record{"statsUserUplink": true, "statsUserDownlink": true}}},
	}
	for _, drift := range []bool{false, true} {
		reads := 0
		run := func(_ context.Context, command string, _ int) (string, error) {
			if command == "base64 < '/usr/local/etc/xray/config.json'" {
				reads++
				raw, err := json.Marshal(doc)
				if drift && reads == 2 {
					raw = append(raw, '\n')
				}
				return base64.StdEncoding.EncodeToString(raw), err
			}
			return `{"stat":[{"name":"user>>>alice>>>traffic>>>uplink","value":"1234"},{"name":"user>>>other>>>traffic>>>uplink","value":"9000"}]}`, nil
		}
		result, err := readCoreUser(context.Background(), "xray", state, binding, run)
		if err != nil {
			t.Fatal(err)
		}
		if drift {
			if result["reading"] != nil || result["counterError"] == nil {
				t.Fatal("concurrent drift should invalidate the reading")
			}
		} else if reading, ok := result["reading"].(Record); !ok ||
			reading["source"] != "authenticated-client" || reading["up"] != int64(1234) || reading["down"] != int64(0) {
			t.Fatalf("unexpected reading: %v", result["reading"])
		}
	}
}

func TestCoreUserRemovalPlanVerifiesOwnershipAndPreservesOtherUsers(t *testing.T) {
	owner := Record{"email": "alice", "id": "3c5827c6-2f92-4861-a1f8-562d5388bca7"}
	other := Record{"email": "bob", "id": "30403cc4-583b-426a-8424-ec98489977b2"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{owner, other}}}
	binding := bindingFor(t, row, owner)
	binding["inboundId"] = 17
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			manual := Record{"tag": "unmanaged"}
			doc := Record{"inbounds": []any{native, manual}, "outbounds": []any{Record{"tag": "untouched"}}}
			state := legacyCoreState{Inbounds: []Record{row}}
			next, rows, err := planCoreUserChange(kind, "remove", state, doc, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			remaining := anyRecords(rows[0]["settings"].(Record)["clients"])
			if len(remaining) != 1 || remaining[0]["email"] != "bob" ||
				!sameCoreInbound(manual, anyRecords(next["inbounds"])[1]) {
				t.Fatal("removal changed unrelated entries")
			}
			if _, _, err := planCoreUserChange(kind, "remove", state, next, binding, false); err == nil {
				t.Fatal("changed remote configuration accepted without recovery intent")
			}
			retried, _, err := planCoreUserChange(kind, "remove", state, next, binding, true)
			if err != nil || !sameCoreInbound(next, retried) {
				t.Fatal("retry did not produce the same configuration")
			}
			again, _, err := planCoreUserChange(kind, "remove", legacyCoreState{Inbounds: rows}, next, binding, false)
			if err != nil || again != nil {
				t.Fatal("already removed user should be a no-op")
			}
			bad := bindingFor(t, row, other)
			bad["inboundId"], bad["userEmail"] = 17, "alice"
			if _, _, err := planCoreUserChange(kind, "remove", state, doc, bad, false); err == nil {
				t.Fatal("incorrect credential hash accepted")
			}
		})
	}
}

func TestCoreUserPauseAndResumePreserveIdentity(t *testing.T) {
	user := Record{"email": "alice", "id": "3c5827c6-2f92-4861-a1f8-562d5388bca7"}
	other := Record{"email": "bob", "id": "30403cc4-583b-426a-8424-ec98489977b2"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
		"settings": Record{"clients": []any{user, other}}}
	binding := bindingFor(t, row, user)
	binding["inboundId"], binding["monthlyPaused"] = 17, true
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			doc := Record{"inbounds": []any{native}}
			state := legacyCoreState{Inbounds: []Record{row}}
			paused, rows, err := planCoreUserChange(kind, "pause", state, doc, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			pausedUser, err := FindUser(rows[0], binding, false)
			if err != nil || pausedUser["enable"] != false || sameCoreInbound(doc, paused) {
				t.Fatal("pause should keep the binding but remove its native authorization")
			}
			state.Inbounds = rows
			binding["monthlyBaselinePending"] = true
			if _, _, err := planCoreUserChange(kind, "resume", state, paused, binding, false); err == nil {
				t.Fatal("resume accepted without a new baseline")
			}
			delete(binding, "monthlyBaselinePending")
			resumed, rows, err := planCoreUserChange(kind, "resume", state, paused, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			resumedUser, err := FindUser(rows[0], binding, false)
			if err != nil || resumedUser["enable"] != true || sameCoreInbound(paused, resumed) {
				t.Fatal("resume did not restore the bound credential")
			}
			retry, _, err := planCoreUserChange(kind, "resume", state, resumed, binding, true)
			if err != nil || !sameCoreInbound(resumed, retry) {
				t.Fatal("interrupted resume did not produce the same config")
			}
		})
	}
}

func TestCoreAddUsersKeepSeparateCredentialsAndStats(t *testing.T) {
	const listen = "127.0.0.1:10085"
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
				"settings": Record{"clients": []any{}}}
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			doc := Record{"inbounds": []any{native},
				"api":   Record{"tag": "mxioc-user-stats", "listen": listen, "services": []any{"StatsService"}},
				"stats": Record{}, "policy": Record{"levels": Record{"0": Record{"statsUserUplink": true, "statsUserDownlink": true}}},
				"experimental": Record{"v2ray_api": Record{"listen": listen, "stats": Record{"enabled": true, "users": []any{}}}},
			}
			state := legacyCoreState{Inbounds: []Record{row}, UserStats: Record{
				"listen": listen, "binary": "/usr/local/bin/xray", "users": []any{},
			}}
			var first Record
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
				retry, _, err := planCoreUserChange(kind, "add", state, next, binding, true, user)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := extendCoreStats(kind, next, retry, state.UserStats, binding); err != nil || !sameCoreInbound(next, retry) {
					t.Fatal("retry changed provisioned identity or counters")
				}
				state, doc = legacyCoreState{Inbounds: rows, UserStats: stats}, next
				if i == 0 {
					first = user
				} else if first["id"] == user["id"] || first["email"] == user["email"] {
					t.Fatal("credentials reused across users")
				}
			}
			groups, _ := coreCounterIndex(kind, doc, state.UserStats)
			if len(groups["mxioc-inbound-17"].emails) != 2 {
				t.Fatal("both independent users must have accounting")
			}
		})
	}
}

func TestLegacyEnrollmentCannotReplaceMissingOrChangedCredential(t *testing.T) {
	user := Record{"id": "3c5827c6-2f92-4861-a1f8-562d5388bca7", "email": "legacy"}
	row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless", "settings": Record{"clients": []any{user}}}
	binding := bindingFor(t, row, user)
	binding["inboundId"] = 17
	for _, kind := range []string{"xray", "sing-box"} {
		for _, mode := range []string{"missing", "changed", "disabled"} {
			t.Run(kind+"/"+mode, func(t *testing.T) {
				candidate := Record{"id": row["id"], "tag": row["tag"], "port": row["port"], "protocol": row["protocol"], "settings": Record{"clients": []any{}}}
				if mode != "missing" {
					altered := Record{"id": user["id"], "email": user["email"]}
					if mode == "changed" {
						altered["id"] = "30403cc4-583b-426a-8424-ec98489977b2"
					} else {
						altered["enable"] = false
					}
					candidate["settings"].(Record)["clients"] = []any{altered}
				}
				native, err := legacyNativeInbound(kind, candidate)
				if err != nil {
					t.Fatal(err)
				}
				state := legacyCoreState{Inbounds: []Record{candidate}}
				// Enrollment passes nil rather than a new credential, even on journal retry.
				if _, _, err := planCoreUserChange(kind, "add", state, Record{"inbounds": []any{native}}, binding, true, nil); err == nil {
					t.Fatal("enrollment recreated or accepted altered user")
				}
			})
		}
	}
}
