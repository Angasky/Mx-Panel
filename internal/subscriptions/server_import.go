package subscriptions

import (
	"context"
	"errors"
	"strconv"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func (c *Controller) ImportServerInbound(ctx context.Context, profile, server string, inbound int, payload Record) (Record, error) {
	if server == "" || inbound < 1 {
		return nil, errors.New("请选择服务器和入站")
	}
	if raw, exists := payload["bind"]; exists {
		if _, ok := raw.(bool); !ok {
			return nil, errors.New("绑定参数必须为布尔值")
		}
	}
	if payload["bind"] == true {
		managed, err := c.Repository.HasInboundUsers(server, inbound)
		if err != nil {
			return nil, err
		}
		confirmed := payload["confirmed"] == true || payload["confirmedDedicated"] == true
		if !managed || confirmed {
			if raw, exists := payload["indices"]; exists {
				indices, ok := raw.([]any)
				if !ok || len(indices) != 1 {
					return nil, errors.New("专属绑定必须选择唯一连接")
				}
				n, err := number(indices[0], -1)
				if err != nil || n != 0 {
					return nil, errors.New("节点索引无效")
				}
			}
			return c.BindDedicatedInbound(ctx, profile, server, inbound, confirmed)
		}
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
	if err := c.Repository.CheckInboundAvailable(server, inbound); err != nil {
		return nil, err
	}
	snapshot, err := c.Backend.Inbounds(ctx, server)
	if err != nil {
		return nil, err
	}
	var target Record
	for _, row := range objects(snapshot["inbounds"]) {
		if text(row["id"]) == strconv.Itoa(inbound) {
			if target != nil {
				return nil, errors.New("远端入站 ID 重复")
			}
			target = row
		}
	}
	if target == nil || target["enable"] == false {
		return nil, errors.New("远端入站缺失或停用")
	}
	managed, err := c.Repository.HasInboundUsers(server, inbound)
	if err != nil {
		return nil, err
	}
	if managed {
		if !c.started.Load() {
			return nil, errors.New("独立用户后台计量尚未启动")
		}
		if snapshot["readOnly"] == true {
			target = nil
			for _, row := range objects(snapshot["provisionInbounds"]) {
				if text(row["id"]) == strconv.Itoa(inbound) {
					if target != nil {
						return nil, errors.New("远端入站 ID 重复")
					}
					target = row
				}
			}
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		return c.provision(ctx, profile, server, target, nil)
	}
	if payload["bind"] == true {
		return nil, errors.New("整入站绑定请使用独立用户导入；不会自动接管已有认证凭据")
	}
	record, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	var nodes []Record
	if snapshot["readOnly"] == true {
		if target["coreStatus"] != "present" {
			return nil, errors.New("独立内核入站尚未与远端核对")
		}
		raw, ok := target["shareLinks"].([]any)
		if !ok {
			return nil, errors.New("独立内核分享链接格式无效")
		}
		for _, item := range raw {
			uri, ok := item.(string)
			if !ok {
				return nil, errors.New("独立内核分享链接格式无效")
			}
			node, e := links.Parse(uri)
			if e != nil {
				return nil, e
			}
			nodes = append(nodes, node)
		}
	} else {
		nodes, err = remote.InboundNodes(target, record)
	}
	if err != nil || len(nodes) == 0 {
		return nil, errors.New("该入站没有可导入的兼容节点")
	}
	selected := []config.Document{}
	if raw, exists := payload["indices"]; exists {
		indices, ok := raw.([]any)
		if !ok || len(indices) == 0 {
			return nil, errors.New("请选择有效节点索引")
		}
		seen := map[int]bool{}
		for _, raw := range indices {
			n, err := number(raw, -1)
			if err != nil || n < 0 || n >= int64(len(nodes)) || seen[int(n)] {
				return nil, errors.New("节点索引无效或重复")
			}
			seen[int(n)] = true
			selected = append(selected, nodes[int(n)])
		}
	} else {
		selected = nodes
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return c.Repository.ImportUnboundServerNodes(profile, server, inbound, selected, c.Now())
}
