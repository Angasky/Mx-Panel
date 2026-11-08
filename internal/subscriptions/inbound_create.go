package subscriptions

import (
	"context"
	"errors"
	"strconv"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type inboundCreator interface {
	CreateInbound(context.Context, string, string, remote.Record) (remote.Record, error)
}
type relayCreator interface {
	CreateRelay(context.Context, string, string, remote.Record) (remote.Record, error)
}

func (c *Controller) CreateInbound(ctx context.Context, profile, server string, payload Record) (Record, error) {
	if _, raw := payload["inbound"]; raw || payload["template"] == "shadowsocks" {
		return c.createRawPanelInbound(ctx, profile, server, payload)
	}
	return c.createInbound(ctx, profile, server, payload, false, nil, nil)
}
func (c *Controller) CreateRelay(ctx context.Context, profile, server string, payload Record) (Record, error) {
	return c.createInbound(ctx, profile, server, payload, true, nil, nil)
}
func (c *Controller) createInbound(ctx context.Context, profile, server string, payload Record, relay bool, chain *config.ServerChainImport, prepare func() error) (Record, error) {
	if !c.started.Load() {
		return nil, errors.New("独立用户后台计量尚未启动")
	}
	if server == "" {
		return nil, errors.New("请选择服务器")
	}
	if profile == "" {
		profile = "clash"
	}
	backend, ok := c.Backend.(inboundCreator)
	if !ok {
		return nil, errors.New("服务器新建入站尚未适配")
	}
	create := backend.CreateInbound
	if relay {
		r, ok := c.Backend.(relayCreator)
		if !ok {
			return nil, errors.New("服务器中转创建尚未适配")
		}
		create = r.CreateRelay
	}
	release, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer release()
	release, err = c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer release()
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	if err = c.preflight(state, server); err != nil {
		return nil, err
	}
	if prepare != nil {
		if err := prepare(); err != nil {
			return nil, err
		}
	}
	// An empty inbound grants no access. The first usable user is created by the
	// existing durable ownership workflow, with limits rechecked before granting.
	created, err := create(ctx, server, profile, payload)
	if err != nil {
		return nil, err
	}
	row, ok := created["inbound"].(map[string]any)
	if !ok {
		return nil, errors.New("新增入站结果缺少配置，请刷新服务器列表核对")
	}
	id, e := strconv.Atoi(text(row["id"]))
	if e != nil || id < 1 {
		return nil, errors.New("新增入站缺少有效 ID，请刷新核对")
	}
	if err = c.Repository.CheckInboundAvailable(server, id); err != nil {
		return nil, err
	}
	result, err := c.provision(ctx, profile, server, row, chain)
	if err != nil {
		return nil, errors.New("入站 " + strconv.Itoa(id) + " 已创建，订阅独立用户导入待重试：" + err.Error() + "；请在同一窗口重试或从此入站导入，勿重复新建")
	}
	result["inbound"] = row
	result["enforcementEnabled"] = true
	result["reusedInbound"] = created["reused"]
	return result, nil
}
