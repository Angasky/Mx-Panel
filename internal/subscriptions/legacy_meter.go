package subscriptions

import (
	"context"
	"errors"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

type legacyMeterCleaner interface {
	ClearLegacyMeter(context.Context, string, int, int) error
}

func (c *Controller) ClearLegacyMeter(ctx context.Context, profile string, position int, token string, confirmed bool) (Record, error) {
	cleaner, ok := c.Backend.(legacyMeterCleaner)
	if !ok || !confirmed || position < 0 || len(token) != 64 {
		return nil, errors.New("请确认清理旧端口计量，并刷新绑定记录")
	}
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	profile = text(state["id"])
	find := func(state Record) (Record, error) {
		rows := objects(state["remoteNodes"])
		if position >= len(rows) || config.BindingToken(profile, rows[position]) != token {
			return nil, errors.New("订阅绑定已变化，请刷新")
		}
		return rows[position], nil
	}
	binding, err := find(state)
	if err != nil {
		return nil, err
	}
	server := text(binding["serverId"])
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
	state, err = c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	binding, err = find(state)
	if err != nil {
		return nil, err
	}
	id, idErr := number(binding["inboundId"], 0)
	port, portErr := number(binding["port"], 0)
	if idErr != nil || portErr != nil || id < 1 || id > 2147483647 || port < 1 || port > 65535 ||
		binding["scope"] != "user" || binding["counterSource"] != "authenticated-client" ||
		binding["status"] != "active" || binding["inboundDeletePending"] != nil {
		return nil, errors.New("只允许清理已切换到认证用户计量的有效入站")
	}
	profiles, err := c.Repository.ServerProfiles(server)
	if err != nil {
		return nil, err
	}
	for _, owner := range profiles {
		ownerState, err := c.Repository.State(owner)
		if err != nil {
			return nil, err
		}
		for _, row := range objects(ownerState["remoteNodes"]) {
			if row["serverId"] == server && text(row["inboundId"]) == text(binding["inboundId"]) && row["scope"] != "user" &&
				(row["status"] == "active" || row["status"] == "provisioning" || row["inboundDeletePending"] != nil) {
				return nil, errors.New("该入站仍有旧版计量绑定，不能清理")
			}
		}
	}
	sample, err := c.Backend.SubscriptionUser(ctx, server, binding, "read", nil)
	if err != nil {
		return nil, err
	}
	reading, _ := sample["reading"].(Record)
	up, upErr := number(reading["up"], -1)
	down, downErr := number(reading["down"], -1)
	if reading["source"] != "authenticated-client" || upErr != nil || downErr != nil || up < 0 || down < 0 {
		return nil, errors.New("认证用户计数尚未确认，旧规则已保留")
	}
	if err := cleaner.ClearLegacyMeter(ctx, server, int(id), int(port)); err != nil {
		return nil, err
	}
	if err := c.updateBinding(profile, binding, func(_, current Record) error {
		delete(current, "legacyMeterRetained")
		return nil
	}); err != nil {
		return nil, errors.New("远端规则已清理，订阅记录保存待重试")
	}
	info, err := c.Info(profile)
	return Record{"cleared": true, "traffic": info}, err
}
