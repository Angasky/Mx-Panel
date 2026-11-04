package subscriptions

import (
	"context"
	"errors"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type namedRelayDeleter interface {
	DeleteNamedRelay(context.Context, string, int, string, func(remote.Record) error) (remote.Record, error)
}

func (c *Controller) DeleteServerChain(ctx context.Context, profile, name string) (Record, error) {
	return c.deleteServerChain(ctx, profile, name, "")
}

func (c *Controller) deleteServerChain(ctx context.Context, profile, name, deletingGroup string) (Record, error) {
	if strings.TrimSpace(name) == "" {
		return nil, errors.New("请选择服务器链路")
	}
	if profile == "" {
		profile = "clash"
	}
	backend, ok := c.Backend.(namedRelayDeleter)
	if !ok {
		return nil, errors.New("服务器链路删除尚未适配")
	}
	server, id, err := c.Repository.ServerChainDeleteTarget(profile, name, deletingGroup)
	if err != nil {
		return nil, err
	}
	unlock, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer unlock()
	unlockProfile, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlockProfile()
	snapshot, err := c.Backend.Inbounds(ctx, server)
	if err != nil {
		return nil, err
	}
	rows, _, err := inventoryRows(snapshot)
	if err != nil {
		return nil, err
	}
	expected := strings.Repeat("0", 64)
	for _, row := range rows {
		if text(row["id"]) == text(id) {
			if snapshot["readOnly"] == true {
				expected = text(row["deleteToken"])
				if len(expected) != 64 {
					return nil, errors.New("中转入站尚未核对，未删除")
				}
				break
			}
			expected, err = remote.InboundVersion(row)
			if err != nil {
				return nil, err
			}
			break
		}
	}
	observed, err := c.Repository.BindingSnapshot(server)
	if err != nil {
		return nil, err
	}
	result, err := backend.DeleteNamedRelay(ctx, server, id, expected, func(old Record) error {
		return c.Repository.BeginServerChainDelete(profile, name, server, id, old, deletingGroup, expected, observed)
	})
	if err != nil {
		return nil, err
	}
	removed, err := c.Repository.ConfirmInboundDeleted(server, id, observed)
	if err != nil {
		return nil, err
	}
	if err := c.Repository.FinishServerChainDelete(profile, name, server, id, deletingGroup); err != nil {
		return nil, err
	}
	result["removedLocalNodes"] = removed
	return result, nil
}
