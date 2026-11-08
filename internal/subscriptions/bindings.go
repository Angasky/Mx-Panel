package subscriptions

import (
	"context"
	"errors"
	"sort"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func (c *Controller) CleanupBindings(ctx context.Context, profile string, confirmed bool) (Record, error) {
	release, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer release()
	removed, err := c.Repository.CleanupBindings(profile, confirmed)
	if err != nil {
		return nil, err
	}
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	retained := 0
	for _, binding := range objects(state["remoteNodes"]) {
		switch binding["status"] {
		case "detached", "revoked", "missing", "identity_changed":
			if config.BindingCleanupPending(binding) {
				retained++
			}
		}
	}
	info, err := c.Info(profile)
	return Record{"removed": removed, "retainedPending": retained, "traffic": info}, err
}
func (c *Controller) RemoveBinding(ctx context.Context, profile string, index int, token string, confirmed bool) (Record, error) {
	release, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer release()
	if err = c.Repository.RemoveBinding(profile, index, token, confirmed); err != nil {
		return nil, err
	}
	info, err := c.Info(profile)
	return Record{"removed": 1, "traffic": info}, err
}

type registryForgetter interface {
	ForgetServer(string, func(Record, func() error) (Record, error)) (Record, error)
}

func (c *Controller) ForgetServer(ctx context.Context, server string, confirmed bool) (Record, error) {
	backend, ok := c.Backend.(registryForgetter)
	if !ok {
		return nil, errors.New("服务器注册表不支持移除")
	}
	serverRelease, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer serverRelease()
	profiles, err := c.Repository.Profiles()
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, p := range profiles {
		state, err := c.Repository.State(text(p["id"]))
		if err != nil {
			return nil, err
		}
		for _, b := range objects(state["remoteNodes"]) {
			if b["serverId"] == server && (b["status"] == "active" || b["status"] == "provisioning") {
				ids = append(ids, text(p["id"]))
				break
			}
		}
	}
	sort.Strings(ids)
	releases := []func(){}
	defer func() {
		for i := len(releases) - 1; i >= 0; i-- {
			releases[i]()
		}
	}()
	for _, id := range ids {
		release, err := c.lock(ctx, id)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	return backend.ForgetServer(server, func(record Record, commit func() error) (Record, error) {
		policies, _ := record["bandwidths"].(map[string]any)
		if len(policies) > 0 && !confirmed {
			return nil, errors.New("请确认保留远端限速配置并移除服务器")
		}
		return c.Repository.DetachServer(server, confirmed, commit)
	})
}
