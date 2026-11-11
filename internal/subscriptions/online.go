package subscriptions

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type onlineReader interface {
	OnlineUser(context.Context, string, remote.Record) (remote.Record, error)
}

func (c *Controller) Online(ctx context.Context, profile string) (Record, error) {
	release, e := c.lock(ctx, profile)
	if e != nil {
		return nil, e
	}
	defer release()
	state, e := c.Repository.State(profile)
	if e != nil {
		return nil, e
	}
	backend, ok := c.Backend.(onlineReader)
	if !ok {
		return nil, errors.New("在线统计后端不可用")
	}
	bindings := objects(state["remoteNodes"])
	rows := []any{}
	ips := map[string]bool{}
	available, active, failed := 0, 0, 0
	for i, b := range bindings {
		if b["status"] != "active" {
			continue
		}
		active++
		row := Record{"binding": i + 1, "node": b["name"], "status": "unavailable", "token": config.BindingToken(text(state["id"]), b)}
		if active > 64 {
			row["error"] = "单次最多读取 64 个绑定"
			failed++
			rows = append(rows, row)
			continue
		}
		result, err := backend.OnlineUser(ctx, text(b["serverId"]), b)
		if err != nil {
			row["error"] = err.Error()
			failed++
		} else {
			row["status"] = "ok"
			row["ips"] = result["ips"]
			row["source"] = result["source"]
			available++
			for _, p := range objects(result["ips"]) {
				ips[text(p["ip"])] = true
			}
		}
		rows = append(rows, row)
	}
	return Record{"rows": rows, "observedIPs": len(ips), "availableBindings": available, "activeBindings": active, "unavailableBindings": failed, "sampledAt": c.Now().Unix(), "scope": "managed-authenticated-users"}, nil
}

type onlineEnabler interface {
	EnableOnlineUser(context.Context, string, remote.Record) (remote.Record, error)
}

func (c *Controller) EnableOnline(ctx context.Context, profile string, index int, token string) (Record, error) {
	release, e := c.lock(ctx, profile)
	if e != nil {
		return nil, e
	}
	defer release()
	state, e := c.Repository.State(profile)
	if e != nil {
		return nil, e
	}
	bindings := objects(state["remoteNodes"])
	if index < 1 || index > len(bindings) {
		return nil, errors.New("绑定不存在")
	}
	b := bindings[index-1]
	if b["status"] != "active" || token == "" || config.BindingToken(text(state["id"]), b) != token {
		return nil, errors.New("绑定已变化，请重新读取")
	}
	backend, ok := c.Backend.(onlineEnabler)
	if !ok {
		return nil, errors.New("在线统计后端不可用")
	}
	return backend.EnableOnlineUser(ctx, text(b["serverId"]), b)
}
