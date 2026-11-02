package subscriptions

import (
	"context"
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
	"github.com/Angasky/dingzhi-ban/internal/config"
)

func editPolicy(record, payload Record, now time.Time) (Record, error) {
	previous := traffic(record)
	for _, key := range []string{"enabled", "enforce", "preserveUsage"} {
		if v, present := payload[key]; present {
			if _, ok := v.(bool); !ok {
				return nil, errors.New("流量开关及保留用量参数须为布尔值")
			}
		}
	}
	for _, b := range objects(record["remoteNodes"]) {
		if b["monthlyPaused"] == true && (payload["enabled"] == false || payload["enforce"] == false) {
			return nil, errors.New("月额度暂停用户尚未恢复，请先增加额度并同步")
		}
	}
	if payload["enabled"] == false {
		if record["accessRevoked"] == true {
			return nil, errors.New("用户已撤销，请先续期并重新创建节点")
		}
		return nil, nil
	}
	enforce := previous["enforce"] == true
	if v, present := payload["enforce"]; present {
		enforce = v == true
	}
	if enforce && record["accessRevoked"] != true {
		found := false
		for _, b := range objects(record["remoteNodes"]) {
			if b["status"] == "active" || b["status"] == "provisioning" {
				if b["scope"] != "user" {
					return nil, errors.New("旧版入站计量尚未迁移")
				}
				found = true
			}
		}
		if !found {
			return nil, errors.New("请先添加该订阅的独立用户，再启用强制限制")
		}
	}
	units, err := number(previous["multiplierUnits"], 1000)
	if err != nil {
		return nil, err
	}
	if v, present := payload["multiplier"]; present {
		units, err = config.PlanUnits(v)
		if err != nil {
			return nil, err
		}
	}
	next := Record{}
	for k, v := range previous {
		next[k] = v
	}
	next["enabled"] = true
	next["enforce"] = enforce
	next["multiplierUnits"] = units
	next["updatedAt"] = now.Unix()
	for _, key := range []string{"upload", "download", "total", "expire"} {
		v := payload[key]
		if (key == "upload" || key == "download") && payload["preserveUsage"] == true {
			v = previous[key]
		}
		if v == nil && (key == "total" || key == "expire") {
			next[key] = nil
			continue
		}
		n, e := number(v, 0)
		if e != nil || n > 9007199254740991 {
			return nil, errors.New("流量及到期时间须为非负安全整数")
		}
		if (key == "total" || key == "expire") && n == 0 {
			return nil, errors.New("总流量或到期时间须大于零，不限请留空")
		}
		if key == "expire" && n > 253402300799 {
			return nil, errors.New("到期日期超出范围")
		}
		next[key] = n
	}
	used, err := billing.Add(next["upload"].(int64), next["download"].(int64))
	if err != nil || used > 9007199254740991 {
		return nil, errors.New("已用流量超出支持范围")
	}
	return next, nil
}

var errPolicyNeedsLock = errors.New("流量修改需等待用户操作完成")

func savePolicy(record, payload Record, now time.Time) error {
	previous := traffic(record)
	oldUnits, err := number(previous["multiplierUnits"], 1000)
	if err != nil {
		return err
	}
	next, err := editPolicy(record, payload, now)
	if err != nil {
		return err
	}
	// Freeze existing nodes at their old independent rate. Editing a default
	// multiplier never rewrites each node's deliberately configured multiplier.
	for _, b := range objects(record["remoteNodes"]) {
		if b["multiplierUnits"] == nil {
			b["multiplierUnits"] = oldUnits
		}
		if next != nil && next["enforce"] == true && (previous["enforce"] != true || previous["enabled"] != true) {
			b["monthlyBaselinePending"] = true
			b["uploadRemainder"] = int64(0)
			b["downloadRemainder"] = int64(0)
		}
	}
	if next == nil {
		delete(record, "traffic")
	} else {
		record["traffic"] = next
		u, err := usage(record)
		if err != nil {
			return err
		}
		used, e := billing.Add(u.Upload, u.Download)
		if e != nil {
			return e
		}
		if !expired(u, now) && (u.Total == nil || used < *u.Total) {
			delete(record, "accessRevoked")
		}
	}
	return nil
}
func (c *Controller) EditTraffic(ctx context.Context, profile string, payload Record) (Record, error) {
	// Ordinary quota/expiry saves use only the short repository transaction.
	// A durable revocation marker forces serialization with remote operations.
	err := c.Repository.UpdateState(profile, func(record Record) error {
		if record["accessRevoked"] == true {
			return errPolicyNeedsLock
		}
		return savePolicy(record, payload, c.Now())
	})
	if errors.Is(err, errPolicyNeedsLock) {
		unlock, e := c.lock(ctx, profile)
		if e != nil {
			return nil, e
		}
		defer unlock()
		err = c.Repository.UpdateState(profile, func(record Record) error { return savePolicy(record, payload, c.Now()) })
	}
	if err != nil {
		return nil, err
	}
	return c.Info(profile)
}
func (c *Controller) ApplyPlan(ctx context.Context, profile, planID string) (Record, error) {
	plan, err := c.Repository.Plan(planID)
	if err != nil {
		return nil, err
	}
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	check := func(p Record) error {
		if p["accessRevoked"] == true {
			return errors.New("用户已撤销，请先续期并重新创建节点")
		}
		for _, b := range objects(p["remoteNodes"]) {
			if b["monthlyPaused"] == true && plan["resetPeriod"] != "monthly" {
				return errors.New("请先恢复月额度暂停用户，再切换重置周期")
			}
			if b["status"] == "active" || b["status"] == "provisioning" {
				if b["scope"] != "user" {
					return errors.New("旧版入站限速和计量尚未迁移")
				}
				speed, _ := decimalSpeed(plan["speedMbps"])
				if speed != 0 {
					return errors.New("共用用户不支持按用户限速，请选择不限速套餐")
				}
			}
		}
		return nil
	}
	p, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	if err = check(p); err != nil {
		return nil, err
	}
	if _, err = c.syncLocked(ctx, profile, false); err != nil {
		return nil, err
	}
	total, err := config.PlanBytes(plan["monthlyGiB"])
	if err != nil {
		return nil, err
	}
	units, err := config.PlanUnits(plan["multiplier"])
	if err != nil {
		return nil, err
	}
	months, err := number(plan["durationMonths"], 12)
	if err != nil {
		return nil, err
	}
	err = c.Repository.UpdateState(profile, func(record Record) error {
		if err := check(record); err != nil {
			return err
		}
		if traffic(record)["enforce"] == true && traffic(record)["enabled"] == true && text(record["enforcementError"]) != "" {
			return errors.New("原用量结算失败，套餐未套用")
		}
		now := c.Now().UTC()
		previous := traffic(record)
		expire := previous["expire"]
		if previous["planId"] == nil || previous["planId"] == "" {
			expire = billing.Month(now, int(months)).Unix()
		}
		anchor := now.Unix()
		nextReset := any(nil)
		if previous["resetPeriod"] == plan["resetPeriod"] {
			var e error
			anchor, e = number(previous["cycleAnchor"], now.Unix())
			if e != nil || anchor < 1 || anchor > 253402300799 {
				return errors.New("原套餐周期日期无效")
			}
			nextReset = previous["nextResetAt"]
			if nextReset != nil {
				n, e := number(nextReset, 0)
				if e != nil || n < 1 || n > 253402300799 {
					return errors.New("原套餐重置日期无效")
				}
			}
		}
		if plan["resetPeriod"] == "monthly" && nextReset == nil {
			nextReset = billing.Month(time.Unix(anchor, 0).UTC(), 1).Unix()
		}
		if plan["resetPeriod"] != "monthly" {
			nextReset = nil
		}
		payload := Record{"enabled": true, "enforce": previous["enforce"] == true, "preserveUsage": true, "total": total, "expire": expire, "multiplier": plan["multiplier"]}
		if err := savePolicy(record, payload, now); err != nil {
			return err
		}
		t := traffic(record)
		for _, key := range []string{"price", "resetPeriod", "durationMonths", "speedMbps"} {
			t[key] = plan[key]
		}
		t["planId"] = plan["id"]
		t["planName"] = plan["name"]
		t["cycleAnchor"] = anchor
		t["nextResetAt"] = nextReset
		for _, b := range objects(record["remoteNodes"]) {
			b["multiplierUnits"] = units
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c.Info(profile)
}
func decimalSpeed(v any) (float64, error) {
	switch n := v.(type) {
	case int:
		return float64(n), nil
	case int64:
		return float64(n), nil
	case interface{ Float64() (float64, error) }:
		return n.Float64()
	case float64:
		return n, nil
	}
	return 0, errors.New("带宽无效")
}
