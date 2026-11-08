package subscriptions

import (
	"context"
	"errors"
	"strconv"

	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

// Raw configurations and classic single-password SS are administrator
// operations, not subscription grants. Credentials are never claimed for billing.
func (c *Controller) createRawPanelInbound(ctx context.Context, profile, server string, payload Record) (Record, error) {
	if server == "" {
		return nil, errors.New("请选择服务器")
	}
	if payload["template"] == "shadowsocks" {
		if err := remote.ValidatePanelShadowsocks(payload); err != nil {
			return nil, err
		}
	} else if _, err := remote.PrepareRawPanelInbound(payload["inbound"]); err != nil {
		return nil, err
	}
	backend, ok := c.Backend.(inboundCreator)
	if !ok {
		return nil, errors.New("服务器新建入站尚未适配")
	}
	if profile == "" {
		profile = "clash"
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
	if _, err := c.Repository.State(profile); err != nil {
		return nil, err
	}
	record, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	created, err := backend.CreateInbound(ctx, server, profile, payload)
	if err != nil {
		return nil, err
	}
	row, ok := created["inbound"].(map[string]any)
	if !ok {
		return nil, errors.New("新增入站结果缺少配置，请在同一窗口重试核对")
	}
	id, err := strconv.Atoi(text(row["id"]))
	if err != nil || id < 1 {
		return nil, errors.New("新增入站缺少有效 ID，请在同一窗口重试核对")
	}
	share := []any{}
	// Like the Python endpoint, unsupported export must not turn a confirmed
	// creation into an error that invites the administrator to create it again.
	if nodes, err := remote.InboundNodes(row, record); err == nil {
		for _, node := range nodes {
			if uri, err := links.Export(node); err == nil {
				share = append(share, uri)
			}
		}
	}
	return Record{"inbound": row, "shareLinks": share, "bound": false, "enforcementEnabled": false, "reusedInbound": created["reused"], "message": "入站已创建，未自动绑定订阅；可从服务器列表单独导入"}, nil
}
