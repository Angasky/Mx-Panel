package subscriptions

import (
	"context"
	"errors"
	"sort"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type inboundWriter interface {
	UpdateInbound(context.Context, string, int, remote.Record, string, func(remote.Record, remote.Record) error) (remote.Record, error)
	DeleteInbound(context.Context, string, int, string, func(remote.Record) error) (remote.Record, error)
}

func (c *Controller) WriteInbound(ctx context.Context, server string, id int, payload Record, expected string, remove bool) (Record, error) {
	if server == "" || id < 1 || len(expected) != 64 {
		return nil, errors.New("请刷新列表后重新选择入站")
	}
	backend, ok := c.Backend.(inboundWriter)
	if !ok {
		return nil, errors.New("服务器入站写入适配尚未完成")
	}
	unlock, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer unlock()
	profiles, err := c.Repository.ServerProfiles(server)
	if err != nil {
		return nil, err
	}
	sort.Strings(profiles)
	for _, profile := range profiles {
		release, e := c.lock(ctx, profile)
		if e != nil {
			return nil, e
		}
		defer release()
	}
	observed, err := c.Repository.BindingSnapshot(server)
	if err != nil {
		return nil, err
	}
	if !remove {
		return backend.UpdateInbound(ctx, server, id, payload, expected, func(old, next Record) error { return c.Repository.GuardInboundEdit(server, id, old, next) })
	}
	result, err := backend.DeleteInbound(ctx, server, id, expected, func(old Record) error { return c.Repository.BeginInboundDelete(server, id, expected, old, observed) })
	if err != nil {
		return nil, err
	}
	removed, err := c.Repository.ConfirmInboundDeleted(server, id, observed)
	if err != nil {
		return nil, errors.New("远端已删除，本地订阅清理待重试：" + err.Error())
	}
	result["removedLocalNodes"] = removed
	return result, nil
}
