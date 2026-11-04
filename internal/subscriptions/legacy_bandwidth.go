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
	backend, ok := c.Backend.(legacyBandwidthCleaner)
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
	if up == 0 && down == 0 {
		if err := backend.ClearLegacyBandwidth(ctx, server, id, int(port)); err != nil {
			return nil, err
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
		profiles, err := c.Repository.ServerProfiles(server)
		if err != nil {
			return nil, err
		}
		for _, other := range profiles {
			if other == text(state["id"]) {
				continue
			}
			otherState, err := c.Repository.State(other)
			if err != nil {
				return nil, err
			}
			for _, row := range objects(otherState["remoteNodes"]) {
				if row["serverId"] == server && text(row["inboundId"]) == strconv.Itoa(id) &&
					(row["status"] == "active" || row["status"] == "provisioning") {
					return nil, errors.New("该入站仍绑定其他订阅，不能设置端口限速")
				}
			}
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
