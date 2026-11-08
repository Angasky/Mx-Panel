package subscriptions

import (
	"context"
	"encoding/json"
	"testing"
	"time"
)

func TestPlanApplicationPreservesUsageExpiryAndCycle(t *testing.T) {
	c, _, _ := controllerFixture(t)
	now := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	_, err := c.EditTraffic(context.Background(), "clash", Record{"enabled": true, "upload": 12, "download": 34, "total": 1000})
	if err != nil {
		t.Fatal(err)
	}
	info, err := c.ApplyPlan(context.Background(), "clash", "tier-1")
	if err != nil {
		t.Fatal(err)
	}
	if info["used"] != int64(46) || info["expire"] != time.Date(2028, 1, 31, 12, 0, 0, 0, time.UTC).Unix() || text(info["nextResetAt"]) != text(time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC).Unix()) {
		t.Fatal("plan reset usage or wrong calendar", info)
	}
	expire, anchor, next := info["expire"], info["cycleAnchor"], info["nextResetAt"]
	now = now.Add(10 * 24 * time.Hour)
	info, err = c.ApplyPlan(context.Background(), "clash", "tier-2")
	if err != nil || info["used"] != int64(46) || info["expire"] != expire || info["cycleAnchor"] != anchor || info["nextResetAt"] != next || info["total"] != int64(100*1024*1024*1024) {
		t.Fatal("reapply renewed or reset subscription", info, err)
	}
}
func TestFastQuotaEditRetainsIndependentRatesWithoutRemoteCalls(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error {
		traffic(p)["upload"] = int64(15)
		objects(p["remoteNodes"])[0]["multiplierUnits"] = int64(2000)
		return nil
	})
	before := len(b.ops)
	b.offline = true
	info, err := c.EditTraffic(context.Background(), "clash", Record{"preserveUsage": true, "total": 2000, "expire": c.Now().Unix() + 1000, "multiplier": json.Number("0.5")})
	if err != nil || info["used"] != int64(15) || len(b.ops) != before || stateBinding(t, c)["multiplierUnits"] != json.Number("2000") {
		t.Fatal("quota edit contacted server or changed node rate", info, err)
	}
	if _, err = c.ApplyPlan(context.Background(), "clash", "tier-1"); err == nil {
		t.Fatal("applied plan without settling old usage")
	}
	p, _ := c.Repository.State("clash")
	if traffic(p)["planId"] != nil {
		t.Fatal("failed plan partially committed")
	}
}
func TestPlanRateChangeSettlesOldRateAndDoesNotRevoke(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error {
		objects(p["remoteNodes"])[0]["multiplierUnits"] = int64(500)
		traffic(p)["total"] = int64(5)
		return nil
	})
	plan, err := c.Repository.SavePlan(Record{"name": "双倍套餐", "monthlyGiB": 1, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 2})
	if err != nil {
		t.Fatal(err)
	}
	email := text(stateBinding(t, c)["userEmail"])
	b.stats[email]["up"] = int64(10)
	info, err := c.ApplyPlan(context.Background(), "clash", text(plan["id"]))
	if err != nil || info["used"] != int64(5) || info["revoked"] != false {
		t.Fatal("settlement revoked old quota or used wrong rate", info, err)
	}
	b.stats[email]["up"] = int64(20)
	info, err = c.Sync(context.Background(), "clash")
	if err != nil || info["used"] != int64(25) {
		t.Fatal("new rate affected historical traffic", info, err)
	}
}
func TestEnforcementEnableBaselinesDisabledPeriodAndRenewalGuards(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.EditTraffic(context.Background(), "clash", Record{"enforce": false, "preserveUsage": true, "total": 1000}); err != nil {
		t.Fatal(err)
	}
	email := text(stateBinding(t, c)["userEmail"])
	b.stats[email]["up"] = int64(900)
	if _, err = c.EditTraffic(context.Background(), "clash", Record{"enforce": true, "preserveUsage": true, "total": 1000}); err != nil {
		t.Fatal(err)
	}
	info, err := c.Sync(context.Background(), "clash")
	if err != nil || info["used"] != int64(0) {
		t.Fatal("charged disabled period", info, err)
	}
	for _, payload := range []Record{{"upload": true}, {"preserveUsage": "yes"}, {"total": 0}, {"expire": int64(253402300800)}, {"upload": json.Number("9007199254740992")}} {
		if _, err = c.EditTraffic(context.Background(), "clash", payload); err == nil {
			t.Fatal("invalid traffic accepted", payload)
		}
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error { objects(p["remoteNodes"])[0]["monthlyPaused"] = true; return nil })
	if _, err = c.EditTraffic(context.Background(), "clash", Record{"enabled": false}); err == nil {
		t.Fatal("disabled control with paused users")
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error {
		delete(objects(p["remoteNodes"])[0], "monthlyPaused")
		p["accessRevoked"] = true
		return nil
	})
	if _, err = c.ApplyPlan(context.Background(), "clash", "tier-1"); err == nil {
		t.Fatal("plan silently revived revoked credentials")
	}
	if _, err = c.EditTraffic(context.Background(), "clash", Record{"enforce": false, "preserveUsage": true, "total": 1000, "expire": 1}); err != nil {
		t.Fatal(err)
	}
	p, _ := c.Repository.State("clash")
	if p["accessRevoked"] != true {
		t.Fatal("disabling enforcement bypassed revocation without renewal")
	}
	if _, err = c.EditTraffic(context.Background(), "clash", Record{"enforce": true, "preserveUsage": true, "total": 1000, "expire": c.Now().Unix() + 86400}); err != nil {
		t.Fatal("explicit renewal rejected", err)
	}
}

func TestNodeMultiplierSettlesOnlyTargetAndKeepsPeerRate(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1, 2}); err != nil {
		t.Fatal(err)
	}
	p, _ := c.Repository.State("clash")
	bindings := objects(p["remoteNodes"])
	b.stats[text(bindings[0]["userEmail"])]["up"] = int64(100)
	b.stats[text(bindings[1]["userEmail"])]["up"] = int64(200)
	_ = c.Repository.UpdateState("clash", func(p Record) error { p["enforcementError"] = "其他服务器离线"; return nil })
	before := len(b.ops)
	if _, err := c.SetMultiplier(context.Background(), "clash", "s", 1, 2000); err != nil {
		t.Fatal(err)
	}
	if len(b.ops) != before+1 {
		t.Fatal("node rate update polled unrelated bindings")
	}
	p, _ = c.Repository.State("clash")
	bindings = objects(p["remoteNodes"])
	if traffic(p)["upload"] != json.Number("100") || bindings[1]["up"] != json.Number("0") || bindings[1]["multiplierUnits"] != json.Number("1000") {
		t.Fatal("target settlement changed peer accounting")
	}
	b.stats[text(bindings[0]["userEmail"])]["up"] = int64(150)
	info, err := c.Sync(context.Background(), "clash")
	if err != nil || info["used"] != int64(400) {
		t.Fatal("historical or peer usage used new node rate", info, err)
	}
}

func TestStringPlanSpeedCannotBypassSharedUserGuard(t *testing.T) {
	for _, speed := range []any{"0.125", "2.5", json.Number("0.125"), 0.125} {
		c, b, _ := controllerFixture(t)
		ctx := context.Background()
		if _, err := c.Batch(ctx, "clash", "s", []int{1}); err != nil {
			t.Fatal(err)
		}
		plan, err := c.Repository.SavePlan(Record{"name": "limited", "monthlyGiB": 10, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": speed, "multiplier": 1})
		if err != nil {
			t.Fatal(err)
		}
		calls := len(b.ops)
		if _, err = c.ApplyPlan(ctx, "clash", text(plan["id"])); err == nil {
			t.Fatal("shared user accepted port rate", speed)
		}
		state, err := c.Repository.State("clash")
		if err != nil || traffic(state)["planId"] != nil || len(b.ops) != calls {
			t.Fatal("rejected plan changed state or contacted server", err)
		}
	}
}

func TestMonthlyResetWithoutEnforcementAndExpiredGuard(t *testing.T) {
	for _, expired := range []bool{false, true} {
		c, b, _ := controllerFixture(t)
		now := time.Date(2027, 3, 1, 12, 0, 0, 0, time.UTC)
		c.Now = func() time.Time { return now }
		err := c.Repository.UpdateState("clash", func(p Record) error {
			expire := now.Add(365 * 24 * time.Hour).Unix()
			if expired {
				expire = now.Unix()
			}
			p["traffic"] = Record{"enabled": true, "enforce": false, "upload": 12, "download": 34, "rawUpload": 20, "rawDownload": 40, "resetPeriod": "monthly", "cycleAnchor": time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC).Unix(), "nextResetAt": time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC).Unix(), "expire": expire}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		info, err := c.Sync(context.Background(), "clash")
		if err != nil {
			t.Fatal(err)
		}
		want := int64(0)
		if expired {
			want = 46
		}
		if info["used"] != want || len(b.ops) != 0 {
			t.Fatal("monthly reset depends on enforcement or contacted server", info, b.ops)
		}
		if !expired && (info["rawUsed"] != int64(0) || text(info["nextResetAt"]) != text(time.Date(2027, 3, 31, 12, 0, 0, 0, time.UTC).Unix())) {
			t.Fatal("calendar drift or raw usage not reset", info)
		}
	}
}

func TestLegacyZeroDecimalSpeedAllowsSharedProvisioning(t *testing.T) {
	for _, speed := range []any{json.Number("0.0"), "0.000", " 0e2 "} {
		c, _, _ := controllerFixture(t)
		if err := c.Repository.UpdateState("clash", func(p Record) error {
			p["traffic"] = Record{"enabled": true, "enforce": false, "speedMbps": speed}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		result, err := c.Batch(context.Background(), "clash", "s", []int{1})
		if err != nil || result["succeeded"] != 1 {
			t.Fatal("legacy zero rate blocked shared user", speed, result, err)
		}
	}
}
