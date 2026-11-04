package subscriptions

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

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
	paths, err := c.Repository.BeginFailoverDelete(profile, name)
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
