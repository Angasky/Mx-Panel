package subscriptions

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
)

// Start is explicit: constructing a web handler or test fixture does not launch
// background network activity. The caller owns shutdown through ctx.
func (c *Controller) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !c.started.CompareAndSwap(false, true) {
		return errors.New("订阅计量已经启动")
	}
	go func() {
		defer c.started.Store(false)
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			c.sweep(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
	return nil
}
func (c *Controller) sweep(ctx context.Context) {
	profiles, err := c.Repository.Profiles()
	if err != nil {
		return
	}
	jobs := make(chan string)
	var group sync.WaitGroup
	for i := 0; i < 4; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			for id := range jobs {
				if ctx.Err() != nil {
					return
				}
				sampleCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				_, _ = c.Sync(sampleCtx, id)
				cancel()
			}
		}()
	}
	for _, p := range profiles {
		select {
		case jobs <- text(p["id"]):
		case <-ctx.Done():
			close(jobs)
			group.Wait()
			return
		}
	}
	close(jobs)
	group.Wait()
}
func resetCycle(p Record, now time.Time) error {
	t := traffic(p)
	if t["resetPeriod"] != "monthly" {
		return nil
	}
	anchor, err := number(t["cycleAnchor"], 0)
	if err != nil {
		return err
	}
	next, err := number(t["nextResetAt"], 0)
	if err != nil {
		return err
	}
	u, err := usage(p)
	if err != nil {
		return err
	}
	if anchor == 0 || next == 0 || now.Unix() < next || u.Expire != nil && *u.Expire <= now.Unix() {
		return nil
	}
	start := time.Unix(anchor, 0).UTC()
	months := (now.Year()-start.Year())*12 + int(now.Month()) - int(start.Month())
	if months < 1 {
		months = 1
	}
	if months > 120000 {
		return errors.New("月度重置日期超出范围")
	}
	for billing.Month(start, months).Unix() <= now.Unix() {
		months++
	}
	for _, k := range []string{"upload", "download", "rawUpload", "rawDownload"} {
		t[k] = int64(0)
	}
	t["nextResetAt"] = billing.Month(start, months).Unix()
	t["updatedAt"] = now.Unix()
	for _, b := range objects(p["remoteNodes"]) {
		b["monthlyBaselinePending"] = true
		b["uploadRemainder"] = int64(0)
		b["downloadRemainder"] = int64(0)
	}
	return nil
}
func (c *Controller) Sync(ctx context.Context, profile string) (Record, error) {
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.syncLocked(ctx, profile, true)
}

func (c *Controller) syncLocked(ctx context.Context, profile string, enforce bool) (Record, error) {
	failures := c.reconcileProfileLocked(ctx, profile)
	p, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	u, err := usage(p)
	if err != nil {
		return nil, err
	}
	if !u.Enabled || !u.Enforce {
		return c.finishSync(profile, failures)
	}
	if err = c.Repository.UpdateState(profile, func(p Record) error { return resetCycle(p, c.Now().UTC()) }); err != nil {
		return nil, err
	}
	p, err = c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	for _, b := range objects(p["remoteNodes"]) {
		if b["status"] != "active" && b["status"] != "provisioning" {
			continue
		}
		if b["scope"] != "user" {
			failures = append(failures, "旧版入站计量尚未迁移，未执行远端操作")
			continue
		}
		if ctx.Err() != nil {
			failures = append(failures, "用量采集被中断，下次继续")
			break
		}
		// Expiry and previously reached quotas remain enforceable even when
		// counter collection is unavailable. Removal still validates identity.
		current, e := c.Repository.State(profile)
		if e != nil {
			return nil, e
		}
		state, e := usage(current)
		if e != nil {
			return nil, e
		}
		if enforce && state.Blocked(c.Now()) && !(traffic(current)["resetPeriod"] == "monthly" && !expired(state, c.Now())) {
			continue
		}
		response, e := c.Backend.SubscriptionUser(ctx, text(b["serverId"]), b, "read", nil)
		if e != nil {
			failures = append(failures, "用户采集或身份核验失败，保留归属等待重试")
			continue
		}
		reading, ok := response["reading"].(map[string]any)
		if !ok {
			failures = append(failures, "缺少认证用户计数，未使用入站总流量代替")
			continue
		}
		if e = c.applyReading(profile, b, reading); e != nil {
			failures = append(failures, e.Error())
		}
	}
	if !enforce {
		return c.finishSync(profile, failures)
	}
	p, err = c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	u, err = usage(p)
	if err != nil {
		return nil, err
	}
	blocked := u.Blocked(c.Now())
	monthly := traffic(p)["resetPeriod"] == "monthly" && !expired(u, c.Now()) && !u.Revoked
	// A fast quota save can occur during collection. Decide revocation again
	// while holding the storage lock before marking access irreversibly revoked.
	if err = c.Repository.UpdateState(profile, func(current Record) error {
		latest, e := usage(current)
		if e != nil {
			return e
		}
		blocked = latest.Blocked(c.Now())
		monthly = traffic(current)["resetPeriod"] == "monthly" && !expired(latest, c.Now()) && !latest.Revoked
		if blocked && !monthly {
			current["accessRevoked"] = true
		}
		p = current
		return nil
	}); err != nil {
		return nil, err
	}
	for _, b := range objects(p["remoteNodes"]) {
		if b["scope"] != "user" || b["status"] != "active" && b["status"] != "provisioning" {
			continue
		}
		op := ""
		if blocked {
			if monthly {
				op = "pause"
			} else {
				op = "remove"
			}
		} else if b["monthlyPaused"] == true {
			op = "resume"
		}
		if op == "" {
			continue
		}
		if op == "resume" && b["inboundDeletePending"] != nil {
			failures = append(failures, "入站删除结果待核对，暂停自动恢复用户")
			continue
		}
		if op == "resume" && b["monthlyBaselinePending"] == true {
			failures = append(failures, "跨月计数基线尚未确认，用户保持暂停")
			continue
		}
		if op == "pause" && b["monthlyPaused"] != true {
			response, e := c.Backend.SubscriptionUser(ctx, text(b["serverId"]), b, "read", nil)
			if e != nil {
				failures = append(failures, "月额度已用尽，用户暂停待重试")
				continue
			}
			client, ok := response["client"].(map[string]any)
			if !ok || client["enable"] == false {
				failures = append(failures, "用户已手动停用，不接管自动恢复")
				continue
			}
			if err = c.updateBinding(profile, b, func(record Record, current Record) error {
				latest, e := usage(record)
				if e != nil {
					return e
				}
				if !latest.Blocked(c.Now()) {
					return errQuotaChanged
				}
				current["monthlyPaused"] = true
				return nil
			}); err != nil {
				if errors.Is(err, errQuotaChanged) {
					continue
				}
				return nil, err
			}
		}
		if _, e := c.Backend.SubscriptionUser(ctx, text(b["serverId"]), b, op, nil); e != nil {
			failures = append(failures, "用户暂停、恢复或撤销待重试，未操作其他用户")
			continue
		}
		if err = c.updateBinding(profile, b, func(_ Record, current Record) error {
			if op == "remove" {
				current["status"] = "revoked"
				current["revokedAt"] = c.Now().Unix()
				delete(current, "pendingUser")
			}
			if op == "resume" {
				delete(current, "monthlyPaused")
			}
			current["error"] = ""
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return c.finishSync(profile, failures)
}

var errQuotaChanged = errors.New("采集期间额度已调整")

func (c *Controller) finishSync(profile string, failures []string) (Record, error) {
	err := c.Repository.UpdateState(profile, func(p Record) error {
		p["lastEnforcedAt"] = c.Now().Unix()
		p["enforcementError"] = strings.Join(failures, "；")
		return nil
	})
	if err != nil {
		return nil, err
	}
	return c.Info(profile)
}
func expired(u billing.Usage, now time.Time) bool { return u.Expire != nil && *u.Expire <= now.Unix() }
func (c *Controller) applyReading(profile string, b, reading Record) error {
	return c.updateBinding(profile, b, func(p, current Record) error {
		return c.applyReadingToBinding(p, current, reading)
	})
}

func (c *Controller) applyReadingToBinding(p, current, reading Record) error {
	up, err := number(reading["up"], -1)
	if err != nil || up < 0 {
		return errors.New("认证用户上传计数无效")
	}
	down, err := number(reading["down"], -1)
	if err != nil || down < 0 {
		return errors.New("认证用户下载计数无效")
	}
	if reading["source"] != "authenticated-client" {
		return errors.New("计数来源不属于独立用户，停止计费")
	}

	t := traffic(p)
	oldUp, e := number(current["up"], 0)
	if e != nil {
		return e
	}
	oldDown, e := number(current["down"], 0)
	if e != nil {
		return e
	}
	defaultUnits, e := number(t["multiplierUnits"], 1000)
	if e != nil {
		return e
	}
	units, e := number(current["multiplierUnits"], defaultUnits)
	if e != nil {
		return e
	}
	ur, e := number(current["uploadRemainder"], 0)
	if e != nil {
		return e
	}
	dr, e := number(current["downloadRemainder"], 0)
	if e != nil {
		return e
	}
	source := text(current["counterSource"])
	if source == "pending" {
		source = ""
	}
	previous := billing.Binding{Up: oldUp, Down: oldDown, UpRemainder: ur, DownRemainder: dr, MultiplierUnits: units, Source: source}
	if current["monthlyBaselinePending"] == true {
		previous.Up = up
		previous.Down = down
		previous.Source = "authenticated-client"
		previous.UpRemainder = 0
		previous.DownRemainder = 0
	}
	delta, e := billing.Compute(previous, billing.Counter{Up: up, Down: down, Source: "authenticated-client"})
	if e != nil {
		return e
	}
	for _, pair := range []struct {
		key   string
		delta int64
	}{{"upload", delta.BilledUp}, {"download", delta.BilledDown}, {"rawUpload", delta.RawUp}, {"rawDownload", delta.RawDown}} {
		n, e := number(t[pair.key], 0)
		if e != nil {
			return e
		}
		next, e := billing.Add(n, pair.delta)
		if e != nil {
			return e
		}
		t[pair.key] = next
	}
	current["up"] = up
	current["down"] = down
	current["uploadRemainder"] = delta.Next.UpRemainder
	current["downloadRemainder"] = delta.Next.DownRemainder
	current["counterSource"] = "authenticated-client"
	current["lastSampleAt"] = c.Now().Unix()
	current["error"] = ""
	delete(current, "monthlyBaselinePending")
	if current["status"] == "provisioning" {
		current["status"] = "active"
	}
	t["updatedAt"] = c.Now().Unix()
	p["traffic"] = t
	return nil
}

func (c *Controller) SetMultiplier(ctx context.Context, profile, server string, inbound int, units int64) (Record, error) {
	if units < 0 || units > 100000 {
		return nil, errors.New("倍率范围为 0–100")
	}
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	p, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	u, err := usage(p)
	if err != nil {
		return nil, err
	}
	if !u.Enabled || !u.Enforce {
		return nil, errors.New("请先启用独立用户计量")
	}
	var binding Record
	for _, b := range objects(p["remoteNodes"]) {
		if text(b["serverId"]) == server && text(b["inboundId"]) == fmt.Sprint(inbound) && b["scope"] == "user" && b["status"] == "active" {
			if binding != nil {
				return nil, errors.New("存在重复节点归属，请先核对")
			}
			binding = b
		}
	}
	if binding == nil {
		return nil, errors.New("有效节点绑定不存在")
	}
	response, err := c.Backend.SubscriptionUser(ctx, server, binding, "read", nil)
	if err != nil {
		return nil, errors.New("目标节点原倍率结算失败")
	}
	reading, ok := response["reading"].(map[string]any)
	if !ok {
		return nil, errors.New("目标节点缺少独立用户计数")
	}
	if err = c.applyReading(profile, binding, reading); err != nil {
		return nil, err
	}
	err = c.updateBinding(profile, binding, func(record, current Record) error {
		u, e := usage(record)
		if e != nil {
			return e
		}
		if !u.Enabled || !u.Enforce {
			return errors.New("计量设置已变化，请刷新")
		}
		current["multiplierUnits"] = units
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Record{"serverId": server, "inboundId": inbound, "multiplier": float64(units) / 1000}, nil
}
