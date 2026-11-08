package config

import (
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

// Cancellation is durable before contacting any server. A failed or offline
// cleanup cannot be resumed as a creation task after a process restart.
func (r *Repository) RequestFailoverCancel(profile, name string) error {
	return r.UpdateState(profile, func(state Document) error {
		draft, err := findFailover(state, "failoverDrafts", name)
		if err != nil || draft == nil {
			return err
		}
		if _, _, err := draftCancelPaths(state, draft); err != nil {
			return err
		}
		draft["cancelRequested"] = true
		return nil
	})
}
func (r *Repository) GuardCanceledCreate(profile, request, server string, id int, row Document) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	state, err := stateRecord(index, profile)
	if err != nil {
		return err
	}
	authorized := false
	for _, raw := range rows(state, "failoverDrafts") {
		draft := raw.(Document)
		if draft["cancelRequested"] != true {
			continue
		}
		for _, key := range rows(draft, "pathRequests") {
			if key == request {
				authorized = true
			}
		}
	}
	if !authorized {
		return errors.New("主备取消意图不存在")
	}
	owned := false
	for _, raw := range rows(index, "profiles") {
		owner := raw.(Document)
		for _, raw := range rows(owner, "remoteNodes") {
			b := raw.(Document)
			if b["serverId"] != server || !bindingInboundID(b, id) {
				continue
			}
			if owner["id"] != state["id"] || b["chainRequest"] != request {
				return errors.New("待取消入站已被其他订阅或链路使用")
			}
			owned = true
			if row != nil {
				if b["scope"] != "user" {
					return errors.New("取消入站存在非用户归属")
				}
				if err := remote.VerifyDedicatedBinding(row, b, b["status"] == "revoked" || b["status"] == "missing"); err != nil {
					return err
				}
				if err := checkInboundBinding(row, b); err != nil {
					return err
				}
			}
		}
	}
	if !owned && row != nil {
		settings, ok := row["settings"].(Document)
		if text, yes := row["settings"].(string); yes {
			if json.Unmarshal([]byte(text), &settings) != nil {
				return errors.New("待取消入站用户格式无效")
			}
			ok = true
		}
		if !ok {
			return errors.New("待取消入站用户格式无效")
		}
		if clients, exists := settings["clients"]; exists {
			list, ok := clients.([]any)
			if !ok || len(list) != 0 {
				return errors.New("待取消入站含未登记用户，不能删除")
			}
		}
	}
	return nil
}
