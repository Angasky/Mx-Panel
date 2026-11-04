package subscriptions

import (
	"context"
	"errors"
	"strconv"
)

type legacyBandwidthCleaner interface {
	ClearLegacyBandwidth(context.Context, string, int, int) error
}

func (c *Controller) ClearLegacyBandwidth(ctx context.Context, profile, server string, id int) (Record, error) {
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
	if err := backend.ClearLegacyBandwidth(ctx, server, id, int(port)); err != nil {
		return nil, err
	}
	cleared := Record{"uploadKbps": 0, "downloadKbps": 0, "appliedAt": c.Now().Unix(), "mode": "policing"}
	if err := c.updateBinding(profile, binding, func(_, row Record) error {
		row["bandwidth"] = cleared
		return nil
	}); err != nil {
		return nil, errors.New("远端限速已清理，订阅记录保存待重试")
	}
	return cleared, nil
}
