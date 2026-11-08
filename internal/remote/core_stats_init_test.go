package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestEnableCoreStatsRecoversAfterInterruptedWrite(t *testing.T) {
	testCoreStatsRecovery(t, false)
}

func TestFirstImportEnablesStatsBeforeGrantingUser(t *testing.T) {
	testCoreStatsRecovery(t, true)
}

func TestLegacyEnrollmentEnablesStatsAndRecoversAfterRestart(t *testing.T) {
	testCoreStatsRecovery(t, true, true)
}

func testCoreStatsRecovery(t *testing.T, importing bool, existingUser ...bool) {
	t.Helper()
	existing := len(existingUser) > 0 && existingUser[0]
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			m, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			server := serverPayload()
			server["installType"] = kind
			delete(server, "panelAddress")
			result, err := m.Save(server)
			if err != nil {
				t.Fatal(err)
			}
			id := value(result["id"])
			row := Record{"id": 17, "tag": "mxioc-inbound-17", "port": 443, "protocol": "vless",
				"settings": Record{"clients": []any{}}}
			state, err := m.SealUser(Record{"inbounds": []any{row}})
			if err != nil {
				t.Fatal(err)
			}
			if err := m.updateCoreUserState(id, "", "", state, ""); err != nil {
				t.Fatal(err)
			}
			client, err := NewUser(row)
			if err != nil {
				t.Fatal(err)
			}
			if existing {
				row["settings"].(Record)["clients"] = []any{client}
				next, err := m.SealUser(Record{"inbounds": []any{row}})
				if err != nil {
					t.Fatal(err)
				}
				if err := m.updateCoreUserState(id, state, "", next, ""); err != nil {
					t.Fatal(err)
				}
			}
			binding := bindingFor(t, row, client)
			binding["inboundId"] = 17
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			raw, err := json.Marshal(Record{"inbounds": []any{native}})
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			run := func(_ context.Context, script string, _ int) (string, error) {
				switch {
				case strings.HasPrefix(script, "base64 < "):
					return base64.StdEncoding.EncodeToString(raw), nil
				case strings.HasPrefix(script, "test -x"), strings.HasPrefix(script, "command -v timeout"):
					return "with_v2ray_api", nil
				case strings.HasPrefix(script, "/usr/local/bin/xray api"):
					return "{}", nil
				}
				_, tail, ok := strings.Cut(script, "printf '%s' '")
				if !ok || (writes < 2 && kind == "xray" && !strings.Contains(script, "timeout 2 /usr/local/bin/xray api statsquery")) || (writes < 2 && kind == "sing-box" && !strings.Contains(script, "true </dev/tcp/127.0.0.1/10085")) {
					t.Fatal("write must verify the running stats service")
				}
				encoded, _, _ := strings.Cut(tail, "'")
				var err error
				raw, err = base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				writes++
				if writes == 1 {
					return "", errors.New("SSH connection lost")
				}
				return "MXIOC_CORE_APPLIED", nil
			}
			failQuery := false
			ctx := context.WithValue(context.Background(), coreStatsQueryKey{}, coreStatsQuery(func(context.Context, string) (string, error) {
				if failQuery {
					return "", errors.New("stats unavailable")
				}
				return "{}", nil
			}))
			enable := func() error {
				record, err := m.Record(id)
				if err != nil {
					return err
				}
				if existing {
					_, err = m.changeCoreUser(ctx, id, kind, "add", record, binding, run, nil)
				} else if importing {
					_, err = m.changeCoreUser(ctx, id, kind, "add", record, binding, run, client)
				} else {
					_, err = m.enableCoreStats(ctx, id, kind, record, run)
				}
				return err
			}
			if err := enable(); err == nil || writes != 1 {
				t.Fatal("unexpected first result", err)
			}
			if !existing && strings.Contains(string(raw), value(client["id"])) {
				t.Fatal("user granted before verifying stats")
			}
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			baseWrites := 2
			if kind == "sing-box" {
				failQuery = true
				if err := enable(); err == nil || writes != 2 {
					t.Fatal("failed query did not stop initialization", err)
				}
				record, err := m.Record(id)
				if err != nil || value(record["coreUserPending"]) == "" {
					t.Fatal("failed query lost recovery journal", err)
				}
				saved, err := m.Secret(record, "coreState")
				if err != nil {
					t.Fatal(err)
				}
				state, err := parseLegacyCoreState(saved)
				if err != nil || len(state.UserStats) != 0 || (!existing && strings.Contains(string(raw), value(client["id"]))) {
					t.Fatal("stats or user committed before gRPC verification", err)
				}
				m, err = Open(root)
				if err != nil {
					t.Fatal(err)
				}
				failQuery = false
				baseWrites = 3
			}
			expectedWrites := baseWrites
			if importing && (!existing || kind == "sing-box") {
				expectedWrites++
			}
			if err := enable(); err != nil || writes != expectedWrites {
				t.Fatal("retry did not finalize", err)
			}
			if err := enable(); err != nil || writes != expectedWrites {
				t.Fatal("retry of completed request must not rewrite configuration", err)
			}
			if importing && strings.Count(string(raw), value(client["id"])) != 1 {
				t.Fatal("exactly one subscription user should exist")
			}
		})
	}
}

func TestPlanCoreStatsRefusesForeignAPIs(t *testing.T) {
	for kind, doc := range map[string]Record{
		"xray":     {"api": Record{"listen": "127.0.0.1:1234"}},
		"sing-box": {"experimental": Record{"v2ray_api": Record{}}},
	} {
		if _, err := planCoreStats(kind, doc); err == nil {
			t.Errorf("%s: existing API overwritten", kind)
		}
	}
}
