package subscriptions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/billing"
	"time"
)

func cycleRepairToken(t Record) string {
	raw, _ := json.Marshal([]any{t["cycleAnchor"], t["nextResetAt"], t["resetPeriod"], t["resetDay"], t["expire"], t["planId"]})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}
func cycleRepairPreview(p Record, now time.Time) Record {
	t := traffic(p)
	out := Record{"profile": p["id"], "name": p["name"], "anchor": t["cycleAnchor"], "nextReset": t["nextResetAt"], "expire": t["expire"], "token": cycleRepairToken(t), "repairable": false}
	if t["resetPeriod"] != "monthly" {
		out["reason"] = "非月度套餐，无周期修复建议"
		return out
	}
	anchor, e := number(t["cycleAnchor"], 0)
	if e != nil || anchor < 1 || anchor > now.Unix() {
		out["reason"] = "开始日缺失或在未来，无法自动推断，请依据订单记录核对"
		return out
	}
	day, e := number(t["resetDay"], 0)
	if e != nil || day > 31 {
		out["reason"] = "重置日配置无效，请先核对套餐"
		return out
	}
	next, e := number(t["nextResetAt"], 0)
	if e != nil {
		out["reason"] = "重置时间格式损坏，需核对备份"
		return out
	}
	if next > now.Unix() {
		out["reason"] = "已有未来重置时间，不自动修改开始日或到期日"
		return out
	}
	if next > anchor {
		out["reason"] = "已到重置日，请先同步流量；不延后应发生的重置"
		return out
	}
	start := time.Unix(anchor, 0).UTC()
	boundary := billing.Month(start, 1)
	if day > 0 {
		boundary = billing.NextResetDay(start, int(day))
	}
	if !boundary.After(now) {
		out["reason"] = "应重置时间已过去，请核对并手动重置流量，不能只把重置日后移"
		return out
	}
	out["repairable"], out["suggestedNextReset"], out["reason"] = true, boundary.Unix(), "开始日可信且周期尚未结束；修复缺失或早于开始日的重置时间，保持已用流量与到期日"
	return out
}
func (c *Controller) PreviewCycleRepair(profile string) (Record, error) {
	p, e := c.Repository.State(profile)
	if e != nil {
		return nil, e
	}
	return cycleRepairPreview(p, c.Now()), nil
}
func (c *Controller) ApplyCycleRepair(ctx context.Context, profile, token string) (Record, error) {
	unlock, e := c.lock(ctx, profile)
	if e != nil {
		return nil, e
	}
	defer unlock()
	e = c.Repository.UpdateState(profile, func(p Record) error {
		t := traffic(p)
		if token == "" || cycleRepairToken(t) != token {
			return errors.New("套餐周期已变化，请重新预览")
		}
		preview := cycleRepairPreview(p, c.Now())
		if preview["repairable"] != true {
			return errors.New("该套餐没有可自动确认的周期修复")
		}
		t["nextResetAt"] = preview["suggestedNextReset"]
		t["cycleRepairedAt"] = c.Now().Unix()
		return nil
	})
	if e != nil {
		return nil, e
	}
	return c.PreviewCycleRepair(profile)
}
