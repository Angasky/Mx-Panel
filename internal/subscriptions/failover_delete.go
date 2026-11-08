package subscriptions

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

type pendingCreateCanceler interface {
	CancelPendingCreates(context.Context, string, []string, func(string, string, int, Record) error) (Record, error)
}

type unsentCreateCanceler interface {
	CancelUnsentCreates(string, []string) error
}

func (c *Controller) DeleteFailover(ctx context.Context, profile, name string) (Record, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("请选择主备组")
	}
	if profile == "" {
		profile = "clash"
	}
	if _, ok := c.Backend.(namedRelayDeleter); !ok {
		return nil, errors.New("主备路径删除尚未适配")
	}
	release, err := c.lock(ctx, "failover:"+profile)
	if err != nil {
		return nil, err
	}
	defer release()
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	draft, requests, err := c.Repository.FailoverDraftCancelPlan(profile, name)
	if err != nil {
		unlock()
		return nil, err
	}
	if len(requests) > 0 {
		if err := c.Repository.RequestFailoverCancel(profile, name); err != nil {
			unlock()
			return nil, err
		}
		if backend, ok := c.Backend.(pendingCreateCanceler); ok {
			_, err := backend.CancelPendingCreates(ctx, profile, requests, func(request, server string, id int, row Record) error {
				return c.Repository.GuardCanceledCreate(profile, request, server, id, row)
			})
			if err != nil {
				unlock()
				return nil, err
			}
		} else {
			canceler, ok := c.Backend.(unsentCreateCanceler)
			if !ok {
				unlock()
				return nil, errors.New("尚不能核对草稿中未完成的远端请求")
			}
			if err := canceler.CancelUnsentCreates(profile, requests); err != nil {
				unlock()
				return nil, err
			}
		}
	}
	if len(requests) > 0 {
		state, err := c.Repository.State(profile)
		if err != nil {
			unlock()
			return nil, err
		}
		wanted := map[string]bool{}
		for _, request := range requests {
			wanted[request] = true
		}
		for _, binding := range objects(state["remoteNodes"]) {
			if !wanted[text(binding["chainRequest"])] {
				continue
			}
			id, err := number(binding["inboundId"], 0)
			if err != nil || id < 1 {
				unlock()
				return nil, errors.New("取消后的归属记录无效")
			}
			server := text(binding["serverId"])
			observed, err := c.Repository.BindingSnapshot(server)
			if err != nil {
				unlock()
				return nil, err
			}
			if _, err = c.Repository.ConfirmInboundDeleted(server, int(id), observed); err != nil {
				unlock()
				return nil, err
			}
		}
	}
	paths, err := c.Repository.BeginFailoverDelete(profile, name, draft)
	unlock()
	if err != nil {
		return nil, err
	}
	for _, path := range paths {
		if _, err := c.deleteServerChain(ctx, profile, path, name); err != nil {
			return nil, fmt.Errorf("主备路径 %s 待清理，请重试删除：%w", path, err)
		}
	}
	unlock, err = c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := c.Repository.FinishFailoverDelete(profile, name); err != nil {
		return nil, err
	}
	return Record{"deleted": true}, nil
}
