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
		if position >= len(rows) || (config.BindingToken(profile, rows[position]) != token && !completedLegacyMigration(profile, rows[position], token)) {
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
	if completedLegacyMigration(profile, binding, token) {
		info, err := c.Info(profile)
		return Record{"migrated": true, "reused": true, "traffic": info, "scope": binding["scope"],
			"counterBaselineRebuilt": binding["legacyMigrationCutover"] == true,
			"legacyMeterRetained":    binding["legacyMeterRetained"] == true}, err
	}
	if binding["scope"] == "user" || binding["status"] != "active" || binding["monthlyPaused"] == true ||
		binding["monthlyBaselinePending"] == true || binding["inboundDeletePending"] != nil ||
		!config.LegacyCounterSource(binding["counterSource"]) {
		return nil, errors.New("只支持未暂停且计数来源可核对的有效旧绑定")
	}
	cutover := binding["counterSource"] != "authenticated-client"
	id := text(binding["inboundId"])
	serverRecord, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	settings, err := legacyMigrationObject(serverRecord, "bandwidths")
	if err != nil {
		return nil, err
	}
	if _, exists := settings[id]; exists {
		return nil, errors.New("入站仍有关联的端口限速资源，请先清理")
	}
	bandwidth, err := legacyMigrationObject(binding, "bandwidth")
	if err != nil {
		return nil, err
	}
	meters, err := legacyMigrationObject(serverRecord, "meters")
	if err != nil {
		return nil, err
	}
	if meter, exists := meters[id]; exists {
		port, portErr := number(binding["port"], 0)
		meterPort, meterErr := number(meter, 0)
		if portErr != nil || meterErr != nil || port < 1 || port > 65535 || port != meterPort {
			return nil, errors.New("旧端口计量登记与绑定端口不一致")
		}
	}
	staleBandwidth := false
	for _, key := range []string{"uploadKbps", "downloadKbps"} {
		rate, err := number(bandwidth[key], 0)
		if err != nil {
			return nil, errors.New("旧绑定的端口限速记录无效")
		}
		staleBandwidth = staleBandwidth || rate != 0
	}
	if staleBandwidth {
		inboundID, idErr := number(binding["inboundId"], 0)
		port, portErr := number(binding["port"], 0)
		if idErr != nil || portErr != nil || !confirmedBandwidthClear(serverRecord, int(inboundID), int(port)) {
			return nil, errors.New("请先清除旧绑定的端口限速")
		}
	}
	snapshot, err := c.Backend.Inbounds(ctx, server)
	if err != nil {
		return nil, err
	}
	available := snapshot["inbounds"]
	if snapshot["readOnly"] == true {
		available = append(append([]any{}, asAnyRows(snapshot["provisionInbounds"])...), asAnyRows(snapshot["dedicatedInbounds"])...)
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
		// A missing historic hash is acceptable only after the repository proves
		// that exactly one stored connection has these same live credentials.
		proposed, err = remote.DedicatedPasswordBinding(row, binding)
	}
	if err != nil {
		return nil, err
	}
	whole := proposed["scope"] == "inbound"
	if whole && binding["counterSource"] == "authenticated-client" {
		return nil, errors.New("不能将认证用户计数自动切换为整入站计数")
	}
	if whole {
		cutover = binding["counterSource"] != "inbound"
	}

	op, err := newToken()
	if err != nil {
		return nil, err
	}
	proposed["operationId"] = op
	if meters[id] != nil && !whole {
		proposed["legacyMeterRetained"] = true
	}
	// Establish exclusive local ownership before any registration. An interrupted
	// core registration can make ordinary reads fail until its journal is resumed.
	nodes, err := remote.InboundNodes(row, serverRecord)
	if err != nil || len(nodes) != 1 {
		return nil, errors.New("无法核对订阅中的唯一连接")
	}
	if err := c.Repository.MigrateLegacyBinding(profile, position, token, proposed, nodes[0], nil); err != nil {
		return nil, err
	}
	var response Record
	if cutover && snapshot["readOnly"] == true && !whole {
		enroller, ok := c.Backend.(legacyCoreUserEnroller)
		if !ok {
			return nil, errors.New("独立内核用户计量尚未就绪")
		}
		// This path requires the existing verified user; it cannot create a
		// replacement credential. It also reconciles a pending add journal.
		response, err = enroller.EnrollLegacyCoreUser(ctx, server, proposed)
	} else {
		response, err = c.subscriptionUser(ctx, server, proposed, "read", nil)
	}
	if err != nil {
		return nil, err
	}
	reading, _ := response["reading"].(Record)
	fresh, _ := response["inbound"].(Record)
	var verified Record
	if whole {
		verified, err = remote.DedicatedPasswordBinding(fresh, proposed)
	} else {
		verified, err = remote.LegacyUserBinding(fresh, binding)
	}
	if err != nil || verified["userHash"] != proposed["userHash"] || verified["identityHash"] != proposed["identityHash"] {
		return nil, errors.New("采样期间远端入站或用户身份已变化")
	}
	if reading["source"] != bindingCounterSource(proposed) {
		return nil, errors.New("认证用户计数不可用，旧绑定已保留")
	}
	nodes, err = remote.InboundNodes(fresh, serverRecord)
	if err != nil || len(nodes) != 1 {
		return nil, errors.New("无法核对订阅中的唯一连接")
	}
	if err := c.Repository.MigrateLegacyBinding(profile, position, token, proposed, nodes[0], func(p, b Record) error {
		if staleBandwidth {
			b["bandwidth"] = Record{"uploadKbps": 0, "downloadKbps": 0, "appliedAt": c.Now().Unix(), "mode": "policing"}
		}
		if cutover {
			up, upErr := number(reading["up"], -1)
			down, downErr := number(reading["down"], -1)
			if upErr != nil || downErr != nil || up < 0 || down < 0 {
				return errors.New("认证用户计数无效，旧绑定已保留")
			}
			b["up"], b["down"], b["counterSource"] = up, down, bindingCounterSource(proposed)
			b["lastSampleAt"], b["lastRawDelta"], b["error"] = c.Now().Unix(), 0, ""
			return nil
		}
		if whole {
			b["scope"], b["dedicated"] = "inbound", true
		}
		return c.applyReadingToBinding(p, b, reading)
	}); err != nil {
		return nil, err
	}
	info, err := c.Info(profile)
	return Record{"migrated": true, "traffic": info, "counterBaselineRebuilt": cutover, "legacyMeterRetained": meters[id] != nil && !whole, "scope": proposed["scope"]}, err
}

// Completed receipts survive restarts, but cannot authorize a different binding
// or restore a revoked/paused user. Replaying only reads local state.
func completedLegacyMigration(profile string, binding Record, token string) bool {
	return binding["legacyMigrationToken"] == token && binding["legacyMigrationGeneration"] == config.BindingToken(profile, binding) && managedBinding(binding) &&
		binding["status"] == "active" && binding["counterSource"] == bindingCounterSource(binding) &&
		binding["monthlyPaused"] != true && binding["monthlyBaselinePending"] != true &&
		binding["inboundDeletePending"] == nil
}

// Legacy fields may be absent, but a present field must be an object. Treating
// malformed state as empty could incorrectly authorize a migration.
func legacyMigrationObject(record Record, field string) (Record, error) {
	raw, exists := record[field]
	if !exists {
		return Record{}, nil
	}
	object, ok := raw.(map[string]any)
	if !ok || object == nil {
		return nil, errors.New("旧迁移记录 " + field + " 必须为 JSON 对象，请先核对数据")
	}
	return object, nil
}
