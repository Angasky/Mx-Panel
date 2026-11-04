package subscriptions

import (
	"context"
	"errors"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type legacyCoreUserEnroller interface {
	EnrollLegacyCoreUser(context.Context, string, remote.Record) (remote.Record, error)
}

func (c *Controller) MigrateLegacyBinding(ctx context.Context, profile string, position int, token string, confirmed bool) (Record, error) {
	if !confirmed || position < 0 || len(token) != 64 {
		return nil, errors.New("请确认迁移并刷新绑定记录")
	}
	initial, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	profile = text(initial["id"])
	lookup := func(state Record) (Record, error) {
		rows := objects(state["remoteNodes"])
		if position >= len(rows) || config.BindingToken(profile, rows[position]) != token {
			return nil, errors.New("绑定记录已变化，请刷新")
		}
		return rows[position], nil
	}
	binding, err := lookup(initial)
	if err != nil {
		return nil, err
	}
	server := text(binding["serverId"])
	serverUnlock, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer serverUnlock()
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	binding, err = lookup(state)
	if err != nil {
		return nil, err
	}
	if binding["scope"] == "user" || binding["status"] != "active" || binding["monthlyPaused"] == true ||
		binding["monthlyBaselinePending"] == true || binding["inboundDeletePending"] != nil ||
		!config.LegacyCounterSource(binding["counterSource"]) {
		return nil, errors.New("只支持未暂停且计数来源可核对的有效旧绑定")
	}
	cutover := binding["counterSource"] != "authenticated-client"
	bandwidth, _ := binding["bandwidth"].(Record)
	for _, key := range []string{"uploadKbps", "downloadKbps"} {
		rate, err := number(bandwidth[key], 0)
		if err != nil || rate != 0 {
			return nil, errors.New("请先清除旧绑定的端口限速")
		}
	}
	id := text(binding["inboundId"])
	serverRecord, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	if settings, ok := serverRecord["bandwidths"].(Record); ok && settings[id] != nil {
		return nil, errors.New("入站仍有关联的端口限速资源，请先清理")
	}
	meters, _ := serverRecord["meters"].(Record)
	snapshot, err := c.Backend.Inbounds(ctx, server)
	if err != nil {
		return nil, err
	}
	available := snapshot["inbounds"]
	if snapshot["readOnly"] == true {
		available = snapshot["provisionInbounds"]
	}
	var row Record
	for _, candidate := range objects(available) {
		if text(candidate["id"]) == id {
			if row != nil {
				return nil, errors.New("远端入站 ID 重复")
			}
			row = candidate
		}
	}
	proposed, err := remote.LegacyUserBinding(row, binding)
	if err != nil {
		return nil, err
	}
	op, err := newToken()
	if err != nil {
		return nil, err
	}
	proposed["operationId"] = op
	response, err := c.Backend.SubscriptionUser(ctx, server, proposed, "read", nil)
	if err != nil {
		return nil, err
	}
	reading, _ := response["reading"].(Record)
	if cutover && snapshot["readOnly"] == true && reading["source"] != "authenticated-client" {
		enroller, ok := c.Backend.(legacyCoreUserEnroller)
		if !ok {
			return nil, errors.New("独立内核用户计量尚未就绪")
		}
		nodes, err := remote.InboundNodes(row, serverRecord)
		if err != nil || len(nodes) != 1 {
			return nil, errors.New("无法核对订阅中的唯一连接")
		}
		if err := c.Repository.MigrateLegacyBinding(profile, position, token, proposed, nodes[0], nil); err != nil {
			return nil, err
		}
		response, err = enroller.EnrollLegacyCoreUser(ctx, server, proposed)
		if err != nil {
			return nil, err
		}
		reading, _ = response["reading"].(Record)
	}
	fresh, _ := response["inbound"].(Record)
	verified, err := remote.LegacyUserBinding(fresh, binding)
	if err != nil || verified["userHash"] != proposed["userHash"] || verified["identityHash"] != proposed["identityHash"] {
		return nil, errors.New("采样期间远端入站或用户身份已变化")
	}
	if reading["source"] != "authenticated-client" {
		return nil, errors.New("认证用户计数不可用，旧绑定已保留")
	}
	nodes, err := remote.InboundNodes(fresh, serverRecord)
	if err != nil || len(nodes) != 1 {
		return nil, errors.New("无法核对订阅中的唯一连接")
	}
	if err := c.Repository.MigrateLegacyBinding(profile, position, token, proposed, nodes[0], func(p, b Record) error {
		if cutover {
			up, upErr := number(reading["up"], -1)
			down, downErr := number(reading["down"], -1)
			if upErr != nil || downErr != nil || up < 0 || down < 0 {
				return errors.New("认证用户计数无效，旧绑定已保留")
			}
			b["up"], b["down"], b["counterSource"] = up, down, "authenticated-client"
			b["lastSampleAt"], b["lastRawDelta"], b["error"] = c.Now().Unix(), 0, ""
			return nil
		}
		return c.applyReadingToBinding(p, b, reading)
	}); err != nil {
		return nil, err
	}
	info, err := c.Info(profile)
	return Record{"migrated": true, "traffic": info, "counterBaselineRebuilt": cutover, "legacyMeterRetained": meters[id] != nil}, err
}
