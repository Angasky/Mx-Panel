package subscriptions

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"maps"
	"strconv"
)

// BindDedicatedInbound adopts the one existing authenticated user. It never
// generates credentials, recreates a missing user, or resets a retry's baseline.
func (c *Controller) BindDedicatedInbound(ctx context.Context, profile, server string, inbound int, confirmed bool) (Record, error) {
	if !confirmed || server == "" || inbound < 1 {
		return nil, errors.New("请确认接管当前订阅的专属单用户入站")
	}
	if !c.started.Load() {
		return nil, errors.New("后台计量尚未启动")
	}
	release, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer release()
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	profile = text(state["id"])
	checked := maps.Clone(state)
	checkedTraffic := maps.Clone(traffic(state))
	checkedTraffic["speedMbps"] = 0
	checked["traffic"] = checkedTraffic
	if err = c.preflight(checked, server); err != nil {
		return nil, err
	}
	if err = c.Repository.CheckInboundAvailable(server, inbound); err != nil {
		return nil, err
	}
	serverRecord, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	standalone := serverRecord["installType"] == "xray" || serverRecord["installType"] == "sing-box"
	var binding Record
	for _, b := range objects(state["remoteNodes"]) {
		if b["serverId"] == server && text(b["inboundId"]) == strconv.Itoa(inbound) {
			if binding != nil || b["dedicated"] != true || (b["status"] != "active" && b["status"] != "provisioning") || b["monthlyPaused"] == true || b["inboundDeletePending"] != nil {
				return nil, errors.New("现有归属或撤销记录不能重新接管")
			}
			binding = b
		}
	}
	// Legacy port resources must be reconciled before switching accounting models.
	for _, field := range []string{"meters", "bandwidths"} {
		object, err := legacyMigrationObject(serverRecord, field)
		if err != nil {
			return nil, err
		}
		if _, exists := object[strconv.Itoa(inbound)]; exists && field != "meters" && binding == nil {
			return nil, errors.New("入站还有旧计量或限速资源，请先核对清理")
		}
	}
	planRate, err := planSpeedKbps(traffic(state)["speedMbps"])
	if err != nil {
		return nil, err
	}
	if binding == nil {
		snapshot, err := c.Backend.Inbounds(ctx, server)
		if err != nil {
			return nil, err
		}
		available := snapshot["inbounds"]
		if standalone {
			available = append(append([]any{}, asAnyRows(snapshot["provisionInbounds"])...), asAnyRows(snapshot["dedicatedInbounds"])...)
		}
		var row Record
		for _, r := range objects(available) {
			if text(r["id"]) == strconv.Itoa(inbound) {
				if row != nil {
					return nil, errors.New("远端入站 ID 重复")
				}
				row = r
			}
		}
		hash, err := remote.LegacyInboundIdentity(row)
		if err != nil {
			return nil, err
		}
		op, err := newToken()
		if err != nil {
			return nil, err
		}
		units, err := number(traffic(state)["multiplierUnits"], 1000)
		if err != nil || units < 0 || units > 100000 {
			return nil, errors.New("节点倍率无效")
		}
		binding, err = remote.LegacyUserBinding(row, Record{"serverId": server, "inboundId": inbound, "identityHash": hash, "operationId": op, "dedicated": true, "status": "provisioning", "name": row["remark"], "port": row["port"], "boundAt": c.Now().Unix(), "up": int64(0), "down": int64(0), "counterSource": "pending", "monthlyBaselinePending": true, "multiplierUnits": units})
		if err != nil {

			binding, err = remote.DedicatedPasswordBinding(row, Record{"serverId": server, "inboundId": inbound, "operationId": op, "status": "provisioning", "name": row["remark"], "port": row["port"], "boundAt": c.Now().Unix(), "counterSource": "pending", "monthlyBaselinePending": true, "multiplierUnits": units})
			if err != nil {
				return nil, err
			}
			if row["enable"] == false {
				return nil, errors.New("入站已停用")
			}
		}
		if planRate > 0 && binding["scope"] != "inbound" {
			return nil, errors.New("按用户计量的入站暂不继承端口限速，请选择不限速套餐")
		}
		nodes, err := remote.InboundNodes(row, serverRecord)
		if err != nil || len(nodes) != 1 {
			return nil, errors.New("无法确认唯一连接")
		}
		binding, err = c.Repository.BeginDedicatedOwnership(profile, binding, nodes[0])
		if err != nil {
			return nil, err
		}
	}
	var response Record
	if standalone && binding["scope"] == "user" {
		enroller, ok := c.Backend.(legacyCoreUserEnroller)
		if !ok {
			return nil, errors.New("独立内核不支持现有用户计量登记")
		}
		response, err = enroller.EnrollLegacyCoreUser(ctx, server, binding)
	} else {
		response, err = c.subscriptionUser(ctx, server, binding, "read", nil)
	}
	if err != nil {
		return nil, err
	}
	fresh, _ := response["inbound"].(Record)
	if fresh == nil || fresh["enable"] == false {
		return nil, errors.New("远端入站缺失或停用")
	}
	if binding["scope"] == "inbound" {
		_, err = remote.DedicatedPasswordBinding(fresh, binding)
	} else {
		err = remote.VerifyDedicatedBinding(fresh, binding, false)
	}
	if err != nil {
		return nil, err
	}
	nodes, err := remote.InboundNodes(fresh, serverRecord)
	if err != nil || len(nodes) != 1 {
		return nil, errors.New("无法确认唯一连接")
	}
	// Recheck profile ownership after remote recovery; no credentials are persisted
	// in the intent and a previous failed import can safely be retried.
	proposed := cloneBindingForReservation(binding)
	if _, err = c.Repository.BeginDedicatedOwnership(profile, proposed, nodes[0]); err != nil {
		return nil, err
	}
	reading, _ := response["reading"].(Record)
	if reading["source"] != bindingCounterSource(binding) {
		return nil, errors.New("认证用户计数不可用，已保留接管记录供重试")
	}
	if err = c.updateBinding(profile, binding, func(p, b Record) error { return c.applyReadingToBinding(p, b, reading) }); err != nil {
		return nil, err
	}
	result, err := c.Repository.ImportOwnedNode(profile, text(binding["operationId"]), nodes[0])
	if err != nil {
		return nil, err
	}
	speed, err := planSpeedKbps(traffic(state)["speedMbps"])
	if err != nil {
		return nil, errors.New("套餐限速无效，绑定已保存")
	}
	if speed > 0 {
		if _, err = c.setBandwidthLocked(ctx, profile, server, inbound, speed, speed); err != nil {
			return nil, err
		}
	}
	result["enforcementEnabled"] = true
	result["dedicated"] = true
	return result, nil
}
func cloneBindingForReservation(binding Record) Record {
	result := Record{}
	for key, value := range binding {
		result[key] = value
	}
	result["status"] = "provisioning"
	return result
}

type dedicatedInboundBackend interface {
	DedicatedInbound(context.Context, string, remote.Record, string) (remote.Record, error)
}

func managedBinding(binding Record) bool {
	return binding["scope"] == "user" || binding["scope"] == "inbound" && binding["dedicated"] == true
}
func bindingCounterSource(binding Record) string {
	if binding["scope"] == "inbound" && binding["dedicated"] == true {
		return "inbound"
	}
	return "authenticated-client"
}
func (c *Controller) subscriptionUser(ctx context.Context, server string, binding Record, operation string, user Record) (Record, error) {
	if binding["scope"] == "inbound" && binding["dedicated"] == true {
		backend, ok := c.Backend.(dedicatedInboundBackend)
		if !ok {
			return nil, errors.New("后端不支持专属入站生命周期")
		}
		return backend.DedicatedInbound(ctx, server, binding, operation)
	}
	return c.Backend.SubscriptionUser(ctx, server, binding, operation, user)
}

func asAnyRows(raw any) []any {
	result := []any{}
	for _, row := range objects(raw) {
		result = append(result, row)
	}
	return result
}
