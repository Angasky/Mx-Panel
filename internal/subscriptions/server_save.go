package subscriptions

import (
	"context"
	"errors"
)

type registrySaver interface{ Save(Record) (Record, error) }

// Serialize identity edits with the first ownership reservation, not just with
// remote SSH calls. A binding may not exist yet when creation acquires its lock.
func (c *Controller) SaveServer(ctx context.Context, payload Record) (Record, error) {
	backend, ok := c.Backend.(registrySaver)
	if !ok {
		return nil, errors.New("服务器注册表不支持保存")
	}
	id := text(payload["id"])
	if id != "" {
		release, err := c.lockServer(ctx, id)
		if err != nil {
			return nil, err
		}
		defer release()
		previous, err := c.Backend.Record(id)
		if err != nil {
			return nil, err
		}
		if err = c.Repository.GuardServerUpdate(id, payload, previous); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return backend.Save(payload)
}
