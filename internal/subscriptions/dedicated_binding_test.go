package subscriptions

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"testing"
	"time"
)

func dedicatedFixture(t *testing.T) (*Controller, *fakeBackend, string) {
	c, b, root := controllerFixture(t)
	b.rows[0]["settings"].(Record)["clients"] = []any{Record{"email": "existing@test", "auth": "unchanged-secret", "enable": true}}
	b.stats["existing@test"] = Record{"up": int64(1234), "down": int64(5678), "source": "authenticated-client"}
	return c, b, root
}
func TestDedicatedBindingBaselineRetryRestartAndExpiry(t *testing.T) {
	c, b, root := dedicatedFixture(t)
	ctx := context.Background()
	result, err := c.BindDedicatedInbound(ctx, "clash", "s", 1, true)
	if err != nil || result["bound"] != true {
		t.Fatal(result, err)
	}
	state, _ := c.Repository.State("clash")
	if n, _ := number(traffic(state)["rawUpload"], 0); n != 0 {
		t.Fatal("billed history")
	}
	c.Repository = &config.Repository{Root: root}
	b.stats["existing@test"]["up"] = int64(1300)
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	state, _ = c.Repository.State("clash")
	if n, _ := number(traffic(state)["rawUpload"], 0); n != 66 {
		t.Fatal("retry lost or duplicated usage", n)
	}
	if b.adds != 0 {
		t.Fatal("created a replacement credential")
	}
	snapshot, _ := c.Repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 1 {
		t.Fatal("duplicate import")
	}
	if err = c.Repository.UpdateState("clash", func(p Record) error {
		tr := traffic(p)
		tr["expire"] = c.Now().Unix() - 1
		p["traffic"] = tr
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err = c.Sync(ctx, "clash"); err != nil {
		t.Fatal(err)
	}
	if stateBinding(t, c)["status"] != "revoked" {
		t.Fatal("expiry did not revoke", stateBinding(t, c))
	}
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err == nil {
		t.Fatal("re-adopted revoked credential")
	}
}
func TestDedicatedBindingFailureRetainsOwnership(t *testing.T) {
	c, b, root := dedicatedFixture(t)
	ctx := context.Background()
	b.missingCounters = true
	if _, err := c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err == nil {
		t.Fatal("accepted missing counters")
	}
	if stateBinding(t, c)["status"] != "provisioning" {
		t.Fatal("lost intent")
	}
	other, err := c.Repository.CreateProfile(Record{"name": "other"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.BindDedicatedInbound(ctx, text(other["id"]), "s", 1, true); err == nil {
		t.Fatal("stole ownership")
	}
	if result, err := c.Batch(ctx, text(other["id"]), "s", []int{1}); err == nil && result["succeeded"] == 1 {
		t.Fatal("added shared user to exclusive inbound")
	}
	c.Repository = &config.Repository{Root: root}
	b.missingCounters = false
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	if b.adds != 0 {
		t.Fatal("created user")
	}
}
func TestDedicatedBindingRejectsUnconfirmedSharedAndChanged(t *testing.T) {
	for _, scenario := range []string{"unconfirmed", "multiple", "disabled", "changed", "other-profile-copy"} {
		t.Run(scenario, func(t *testing.T) {
			c, b, _ := dedicatedFixture(t)
			confirmed := true
			switch scenario {
			case "unconfirmed":
				confirmed = false
			case "multiple":
				b.rows[0]["settings"].(Record)["clients"] = append(b.rows[0]["settings"].(Record)["clients"].([]any), Record{"email": "other", "auth": "other"})
			case "disabled":
				b.rows[0]["enable"] = false
			case "changed":
				b.missingCounters = true
				_, _ = c.BindDedicatedInbound(context.Background(), "clash", "s", 1, true)
				b.missingCounters = false
				b.rows[0]["settings"].(Record)["clients"].([]any)[0].(Record)["auth"] = "replacement"
			case "other-profile-copy":
				other, err := c.Repository.CreateProfile(Record{"name": "other"})
				if err != nil {
					t.Fatal(err)
				}
				if _, err = c.ImportServerInbound(context.Background(), text(other["id"]), "s", 1, Record{}); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := c.BindDedicatedInbound(context.Background(), "clash", "s", 1, confirmed); err == nil {
				t.Fatal("unsafe adoption accepted")
			}
			if b.adds != 0 {
				t.Fatal("created user")
			}
		})
	}
}

type dedicatedCoreBackend struct {
	*fakeBackend
	pending bool
	enrolls int
}

func (b *dedicatedCoreBackend) Inbounds(ctx context.Context, server string) (Record, error) {
	if b.pending {
		return nil, errors.New("pending registration blocks ordinary inventory")
	}
	snapshot, err := b.fakeBackend.Inbounds(ctx, server)
	snapshot["readOnly"], snapshot["provisionInbounds"] = true, snapshot["inbounds"]
	return snapshot, err
}
func (b *dedicatedCoreBackend) EnrollLegacyCoreUser(ctx context.Context, server string, binding Record) (Record, error) {
	b.enrolls++
	if b.enrolls == 1 {
		b.pending = true
		return nil, errors.New("disconnected after apply")
	}
	b.pending = false
	return b.fakeBackend.SubscriptionUser(ctx, server, binding, "read", nil)
}
func TestDedicatedCoreRegistrationRecoversWithoutOrdinaryRead(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			c, base, root := dedicatedFixture(t)
			base.kind = kind
			b := &dedicatedCoreBackend{fakeBackend: base}
			c.Backend = b
			if _, err := c.BindDedicatedInbound(context.Background(), "clash", "s", 1, true); err == nil || !b.pending {
				t.Fatal("expected interruption")
			}
			c.Repository = &config.Repository{Root: root}
			if _, err := c.BindDedicatedInbound(context.Background(), "clash", "s", 1, true); err != nil {
				t.Fatal(err)
			}
			if b.enrolls != 2 || base.adds != 0 || stateBinding(t, c)["status"] != "active" {
				t.Fatal("recovery recreated user or lost ownership")
			}
		})
	}
}
func TestDedicatedMonthlyPauseResumeAndUnbind(t *testing.T) {
	c, b, _ := dedicatedFixture(t)
	ctx := context.Background()
	if _, err := c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	if err := c.Repository.UpdateState("clash", func(p Record) error {
		tr := traffic(p)
		tr["total"] = int64(10)
		tr["resetPeriod"] = "monthly"
		tr["cycleAnchor"] = now.Unix()
		tr["nextResetAt"] = time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC).Unix()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	b.stats["existing@test"]["down"] = int64(5688)
	if _, err := c.Sync(ctx, "clash"); err != nil {
		t.Fatal(err)
	}
	client := b.rows[0]["settings"].(Record)["clients"].([]any)[0].(Record)
	if client["enable"] != false {
		t.Fatal("did not pause")
	}
	now = time.Date(2027, 2, 28, 12, 0, 1, 0, time.UTC)
	b.missingCounters = true
	_, _ = c.Sync(ctx, "clash")
	if client["enable"] != false {
		t.Fatal("resumed without baseline")
	}
	b.missingCounters = false
	_, _ = c.Sync(ctx, "clash")
	if client["enable"] != true {
		t.Fatal("did not resume")
	}
	info, _ := c.Info("clash")
	if info["used"] != int64(0) {
		t.Fatal("billed old month", info)
	}
	before := len(b.ops)
	binding := stateBinding(t, c)
	if _, err := c.RemoveBinding(ctx, "clash", 0, config.BindingToken("clash", binding), true); err != nil {
		t.Fatal(err)
	}
	if len(b.ops) != before || client["enable"] != true {
		t.Fatal("local unbind mutated remote user")
	}
}

func TestDedicatedBindingGuardsWholeInboundEdit(t *testing.T) {
	c, b, _ := dedicatedFixture(t)
	if _, err := c.BindDedicatedInbound(context.Background(), "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	old := clone(b.rows[0])
	next := clone(old)
	settings := next["settings"].(Record)
	settings["clients"] = append(settings["clients"].([]any), Record{"email": "another", "auth": "new-secret"})
	if err := c.Repository.GuardInboundEdit("s", 1, old, next); err == nil {
		t.Fatal("added a second user to an exclusive inbound")
	}
	next = clone(old)
	next["remark"] = "renamed"
	if err := c.Repository.GuardInboundEdit("s", 1, old, next); err != nil {
		t.Fatal(err)
	}
}

type dedicatedPasswordBackend struct{ *fakeBackend }

func (b *dedicatedPasswordBackend) DedicatedInbound(ctx context.Context, server string, binding Record, op string) (Record, error) {
	b.ops = append(b.ops, op)
	if b.offline {
		return nil, errors.New("offline")
	}
	var row Record
	for _, r := range b.rows {
		if text(r["id"]) == text(binding["inboundId"]) {
			row = r
			break
		}
	}
	if row == nil {
		if op == "remove" {
			return Record{"removed": true}, nil
		}
		return nil, errors.New("missing")
	}
	if _, err := remote.DedicatedPasswordBinding(row, binding); err != nil {
		return nil, err
	}
	if op == "remove" {
		b.rows = b.rows[1:]
		return Record{"removed": true}, nil
	}
	if op == "pause" || op == "resume" {
		row["enable"] = op == "resume"
	}
	reading := Record{"source": "inbound", "up": row["up"], "down": row["down"]}
	if b.missingCounters {
		reading = nil
	}
	return Record{"inbound": clone(row), "client": Record{"enable": row["enable"]}, "reading": reading}, nil
}
func TestDedicatedSinglePasswordPanelAccountingAndExpiry(t *testing.T) {
	c, base, root := controllerFixture(t)
	b := &dedicatedPasswordBackend{base}
	c.Backend = b
	row := b.rows[0]
	row["protocol"] = "shadowsocks"
	row["settings"] = Record{"method": "aes-128-gcm", "password": "existing-single-secret"}
	row["streamSettings"] = Record{"network": "tcp", "security": "none"}
	row["up"], row["down"] = int64(1000), int64(2000)
	ctx := context.Background()
	result, err := c.BindDedicatedInbound(ctx, "clash", "s", 1, true)
	if err != nil {
		t.Fatal(result, err)
	}
	if stateBinding(t, c)["scope"] != "inbound" || stateBinding(t, c)["counterSource"] != "inbound" {
		t.Fatal("misrepresented native inbound counters")
	}
	c.Repository = &config.Repository{Root: root}
	row["up"] = int64(1007)
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	state, _ := c.Repository.State("clash")
	if n, _ := number(traffic(state)["upload"], -1); n != 7 {
		t.Fatal("baseline lost", n)
	}
	if _, err = c.SetMultiplier(ctx, "clash", "s", 1, 2000); err != nil {
		t.Fatal(err)
	}
	row["up"] = int64(1010)
	_, _ = c.Sync(ctx, "clash")
	state, _ = c.Repository.State("clash")
	if n, _ := number(traffic(state)["upload"], -1); n != 13 {
		t.Fatal("multiplier incorrect", n)
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["expire"] = c.Now().Unix() - 1; return nil })
	if _, err = c.Sync(ctx, "clash"); err != nil {
		t.Fatal(err)
	}
	if stateBinding(t, c)["status"] != "revoked" || len(b.rows) != 2 || b.adds != 0 {
		t.Fatal("single password expiry did not remove only dedicated inbound")
	}
}

func TestMigrateLegacySinglePasswordUsesStoredCredentialProof(t *testing.T) {
	for _, scenario := range []string{"success", "wrong-secret", "other-owner", "missing-node"} {
		t.Run(scenario, func(t *testing.T) {
			c, base, root := controllerFixture(t)
			b := &dedicatedPasswordBackend{base}
			c.Backend = b
			row := b.rows[0]
			row["protocol"] = "shadowsocks"
			row["settings"] = Record{"method": "aes-128-gcm", "password": "legacy-secret"}
			row["streamSettings"] = Record{"network": "tcp", "security": "none"}
			row["up"], row["down"] = int64(100), int64(200)
			server, _ := b.Record("s")
			nodes, err := remote.InboundNodes(row, server)
			if err != nil || len(nodes) != 1 {
				t.Fatal(err)
			}
			if scenario != "missing-node" {
				if err = c.Repository.Mutate("clash", func(doc Record) error { doc["proxies"] = []any{nodes[0]}; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active", "counterSource": "inbound", "up": 90, "down": 195}
			if err = c.Repository.UpdateState("clash", func(p Record) error {
				p["remoteNodes"] = []any{binding}
				p["traffic"] = Record{"enabled": true, "enforce": true, "upload": 7}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			if scenario == "wrong-secret" {
				row["settings"].(Record)["password"] = "different"
			}
			if scenario == "other-owner" {
				other, err := c.Repository.CreateProfile(Record{"name": "other"})
				if err != nil {
					t.Fatal(err)
				}
				if err = c.Repository.Mutate(text(other["id"]), func(doc Record) error { doc["proxies"] = []any{nodes[0]}; return nil }); err != nil {
					t.Fatal(err)
				}
			}
			token := config.BindingToken("clash", stateBinding(t, c))
			result, err := c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true)
			if scenario != "success" {
				if err == nil {
					t.Fatal("adopted without unique stored credential proof")
				}
				return
			}
			if err != nil || result["migrated"] != true {
				t.Fatal(result, err)
			}
			current := stateBinding(t, c)
			if current["scope"] != "inbound" || current["dedicated"] != true {
				t.Fatal("whole inbound scope missing")
			}
			state, _ := c.Repository.State("clash")
			if n, _ := number(traffic(state)["upload"], -1); n != 17 {
				t.Fatal("old counters not settled", n)
			}
			c.Repository = &config.Repository{Root: root}
			before := len(b.ops)
			if _, err = c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true); err != nil || len(b.ops) != before {
				t.Fatal("replayed completed migration", err)
			}
		})
	}
}
func TestDedicatedSinglePasswordMonthlyLifecycle(t *testing.T) {
	c, base, _ := controllerFixture(t)
	b := &dedicatedPasswordBackend{base}
	c.Backend = b
	row := b.rows[0]
	row["protocol"] = "shadowsocks"
	row["settings"] = Record{"method": "aes-128-gcm", "password": "single-secret"}
	row["streamSettings"] = Record{"network": "tcp", "security": "none"}
	row["up"], row["down"] = int64(100), int64(200)
	ctx := context.Background()
	if _, err := c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	_ = c.Repository.UpdateState("clash", func(p Record) error {
		tr := traffic(p)
		tr["total"] = int64(10)
		tr["resetPeriod"] = "monthly"
		tr["cycleAnchor"] = now.Unix()
		tr["nextResetAt"] = time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC).Unix()
		return nil
	})
	row["down"] = int64(210)
	if _, err := c.Sync(ctx, "clash"); err != nil {
		t.Fatal(err)
	}
	if row["enable"] != false || stateBinding(t, c)["monthlyPaused"] != true {
		t.Fatal("single-password inlet not paused")
	}
	now = time.Date(2027, 2, 28, 12, 0, 1, 0, time.UTC)
	b.missingCounters = true
	_, _ = c.Sync(ctx, "clash")
	if row["enable"] != false {
		t.Fatal("resumed without counters")
	}
	b.missingCounters = false
	_, _ = c.Sync(ctx, "clash")
	if row["enable"] != true || stateBinding(t, c)["monthlyPaused"] == true {
		t.Fatal("single-password inlet not resumed")
	}
	info, _ := c.Info("clash")
	if info["used"] != int64(0) {
		t.Fatal("billed previous month")
	}
}

type dedicatedSpeedBackend struct {
	*bandwidthCleanupBackend
	rates    []int
	policies Record
}

func (b *dedicatedSpeedBackend) DedicatedInbound(ctx context.Context, server string, binding Record, op string) (Record, error) {
	return (&dedicatedPasswordBackend{b.fakeBackend}).DedicatedInbound(ctx, server, binding, op)
}
func (b *dedicatedSpeedBackend) Record(id string) (Record, error) {
	r, err := b.fakeBackend.Record(id)
	r["bandwidths"] = b.policies
	return r, err
}
func (b *dedicatedSpeedBackend) SetLegacyBandwidth(_ context.Context, _ string, _, _ int, up, down int, hash string) error {
	if up != down || len(hash) != 64 {
		return errors.New("invalid bandwidth identity")
	}
	if b.fail {
		return errors.New("rate application interrupted")
	}
	b.rates = append(b.rates, up)
	b.policies["1"] = Record{"port": 24001, "uploadKbps": up, "downloadKbps": down}
	return nil
}
func TestDedicatedPlanSpeedInheritanceRetryAndClear(t *testing.T) {
	c, base, root := controllerFixture(t)
	row := base.rows[0]
	row["protocol"] = "shadowsocks"
	row["settings"] = Record{"method": "aes-128-gcm", "password": "existing-single-secret"}
	row["streamSettings"] = Record{"network": "tcp", "security": "none"}
	row["up"], row["down"] = int64(1000), int64(2000)
	backend := &dedicatedSpeedBackend{bandwidthCleanupBackend: &bandwidthCleanupBackend{fakeBackend: base}, policies: Record{}}
	c.Backend = backend
	ctx := context.Background()
	plan, err := c.Repository.SavePlan(Record{"name": "专属限速", "monthlyGiB": 10, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": "0.125", "multiplier": 1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ApplyPlan(ctx, "clash", text(plan["id"])); err != nil {
		t.Fatal(err)
	}
	backend.fail = true
	if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err == nil {
		t.Fatal("unconfirmed rate accepted")
	}
	c.Repository = &config.Repository{Root: root}
	backend.fail = false
	for i := 0; i < 2; i++ {
		if _, err = c.BindDedicatedInbound(ctx, "clash", "s", 1, true); err != nil {
			t.Fatal(err)
		}
	}
	if len(backend.rates) != 2 || backend.rates[0] != 125 {
		t.Fatal("fractional rate or retry lost", backend.rates)
	}
	plan["speedMbps"] = "2.5"
	if _, err = c.Repository.SavePlan(plan); err != nil {
		t.Fatal(err)
	}
	if _, err = c.ApplyPlan(ctx, "clash", text(plan["id"])); err != nil {
		t.Fatal(err)
	}
	if backend.rates[len(backend.rates)-1] != 2500 {
		t.Fatal("plan rate not applied")
	}
	if _, err = c.ApplyPlan(ctx, "clash", "tier-1"); err != nil {
		t.Fatal(err)
	}
	if backend.calls != 1 || text(stateBinding(t, c)["bandwidth"].(Record)["uploadKbps"]) != "0" {
		t.Fatal("unlimited plan failed to clear rate")
	}
}
