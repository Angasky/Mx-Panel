package subscriptions

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type legacyRelayAdopter interface {
	AdoptLegacyRelay(context.Context, string, int, string, remote.Record) (remote.Record, error)
}

func (c *Controller) AdoptLegacyRelay(ctx context.Context, server string, id int, expected string, evidence Record) (Record, error) {
	backend, ok := c.Backend.(legacyRelayAdopter)
	if !ok {
		return nil, errors.New("旧中转核对尚未适配")
	}
	if server == "" || id < 1 || len(expected) != 64 || evidence["confirmed"] != true {
		return nil, errors.New("请提供原配置并确认中转归属")
	}
	release, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer release()
	return backend.AdoptLegacyRelay(ctx, server, id, expected, evidence)
}
