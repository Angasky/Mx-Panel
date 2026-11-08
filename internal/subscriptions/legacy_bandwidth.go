package subscriptions

import (
	"context"
	"errors"
	"strconv"
)

type legacyBandwidthCleaner interface {
	ClearLegacyBandwidth(context.Context, string, int, int) error
}

type legacyBandwidthSetter interface {
	SetLegacyBandwidth(context.Context, string, int, int, int, int, string) error
}

func (c *Controller) SetBandwidth(ctx context.Context, profile, server string, id, up, down int) (Record, error) {
	_, ok := c.Backend.(legacyBandwidthCleaner)
	if !ok || server == "" || id < 1 {
		return nil, errors.New("请选择可核对的旧限速绑定")
	}
	if profile == "" {
		profile = "clash"
	}
	unlock, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer unlock()
	release, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer release()
	return c.setBandwidthLocked(ctx, profile, server, id, up, down)
}

// Caller holds the server lock followed by the profile lock.
func (c *Controller) setBandwidthLocked(ctx context.Context, profile, server string, id, up, down int) (Record, error) {
	backend, ok := c.Backend.(legacyBandwidthCleaner)
	if !ok {
		return nil, errors.New("后端不支持专属入站限速")
	}
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	var binding Record
	for _, row := range objects(state["remoteNodes"]) {
		if row["serverId"] != server || text(row["inboundId"]) != strconv.Itoa(id) || row["status"] != "active" {
			continue
		}
		if binding != nil || row["scope"] == "user" || row["inboundDeletePending"] != nil {
			return nil, errors.New("只允许清理归属明确的旧版专属入站限速")
		}
		binding = row
	}
	port, err := number(binding["port"], 0)
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("当前订阅没有可核对的旧限速绑定")
	}
	// A port policy affects every user of the inbound. Check ownership for
	// clearing as well as setting, including unfinished operations.
	profiles, err := c.Repository.ServerProfiles(server)
	if err != nil {
		return nil, err
	}
	for _, owner := range profiles {
		ownerState, err := c.Repository.State(owner)
		if err != nil {
			return nil, err
		}
		matches := 0
		for _, row := range objects(ownerState["remoteNodes"]) {
			if row["serverId"] != server || text(row["inboundId"]) != strconv.Itoa(id) {
				continue
			}
			if row["status"] != "active" && row["status"] != "provisioning" && row["inboundDeletePending"] == nil {
				continue
			}
			matches++
			if owner != text(state["id"]) || row["status"] != "active" || row["scope"] == "user" || row["inboundDeletePending"] != nil || matches > 1 {
				return nil, errors.New("该入站还有其他有效或待核对绑定，不能修改或清除端口限速")
			}
		}
	}
	if up == 0 && down == 0 {
		record, err := c.Backend.Record(server)
		if err != nil {
			return nil, err
		}
		if !confirmedBandwidthClear(record, id, int(port)) {
			if err := backend.ClearLegacyBandwidth(ctx, server, id, int(port)); err != nil {
				return nil, err
			}
		}
	} else {
		setter, ok := c.Backend.(legacyBandwidthSetter)
		if !ok {
			return nil, errors.New("此服务器的限速配置尚未适配")
		}
		u, err := usage(state)
		if err != nil {
			return nil, err
		}
		u.Enabled, u.Enforce = true, true
		if u.Blocked(c.Now()) {
			return nil, errors.New("订阅已到期或流量用尽，请先续期")
		}
		if err := setter.SetLegacyBandwidth(ctx, server, id, int(port), up, down, text(binding["identityHash"])); err != nil {
			return nil, err
		}
	}
	applied := Record{"uploadKbps": up, "downloadKbps": down, "appliedAt": c.Now().Unix(), "mode": "policing"}
	if err := c.updateBinding(profile, binding, func(_, row Record) error {
		row["bandwidth"] = applied
		return nil
	}); err != nil {
		return nil, errors.New("远端限速已更新，订阅记录保存待重试")
	}
	return applied, nil
}

// Only a receipt committed after remote confirmation can reconcile stale local
// rates. A present policy, including null, always prevents the shortcut.
func confirmedBandwidthClear(record Record, id, port int) bool {
	policies, ok := record["bandwidths"].(Record)
	cleared, proof := record["goBandwidthCleared"].(Record)
	if !ok || !proof || id < 1 || port < 1 || port > 65535 {
		return false
	}
	key := strconv.Itoa(id)
	_, exists := policies[key]
	return !exists && text(cleared[key]) == strconv.Itoa(port)
}
