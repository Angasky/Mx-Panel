package config

import (
	"errors"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func namedServerChain(record Document, name string) (Document, error) {
	for _, item := range rows(record, "failovers") {
		f, ok := item.(Document)
		if !ok {
			return nil, errors.New("主备归属记录无效")
		}
		if f["name"] == name {
			return nil, errors.New("该链路由主备组管理")
		}
		for _, path := range rows(f, "paths") {
			if path == name {
				return nil, errors.New("该链路由主备组管理")
			}
		}
	}
	var result Document
	for _, item := range rows(record, "serverChains") {
		chain, ok := item.(Document)
		if !ok {
			return nil, errors.New("服务器链路记录无效")
		}
		if chain["name"] == name {
			if result != nil {
				return nil, errors.New("服务器链路名称重复")
			}
			result = chain
		}
	}
	if result == nil {
		return nil, errors.New("服务器链路不存在")
	}
	return result, nil
}

func (r *Repository) ServerChainTarget(profile, name string) (string, int, error) {
	state, err := r.State(profile)
	if err != nil {
		return "", 0, err
	}
	chain, err := namedServerChain(state, name)
	if err != nil {
		return "", 0, err
	}
	server := stringValue(chain["serverId"])
	id, err := integer(chain["inboundId"])
	if server == "" || err != nil || id < 1 {
		return "", 0, errors.New("服务器链路归属无效")
	}
	return server, id, nil
}

func (r *Repository) GuardServerChainDelete(profile, name, server string, id int, inbound Document) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	record, err := stateRecord(index, profile)
	if err != nil {
		return err
	}
	chain, err := namedServerChain(record, name)
	if err != nil {
		return err
	}
	if chain["serverId"] != server || !bindingInboundID(chain, id) {
		return errors.New("服务器链路归属已变化，请刷新")
	}
	var binding Document
	for _, item := range rows(index, "profiles") {
		owner := item.(Document)
		for _, item := range rows(owner, "remoteNodes") {
			candidate := item.(Document)
			if candidate["serverId"] != server || !bindingInboundID(candidate, id) {
				continue
			}
			active := candidate["status"] == "active" || candidate["status"] == "provisioning" || candidate["inboundDeletePending"] != nil
			if active && owner["id"] != record["id"] {
				return errors.New("入站仍被其他订阅使用")
			}
			if owner["id"] != record["id"] || (!active && !(inbound == nil && candidate["status"] == "missing")) {
				continue
			}
			if binding != nil {
				return errors.New("入站存在多条相关绑定，未删除")
			}
			binding = candidate
		}
	}
	if binding == nil {
		return errors.New("服务器链路缺少对应订阅绑定")
	}
	if binding["scope"] != "user" {
		return errors.New("旧链路需要先核对并迁移为独立用户绑定")
	}
	named := false
	for _, item := range rows(binding, "importedNames") {
		if item == name {
			named = true
			break
		}
	}
	if !named {
		return errors.New("链路名称与已导入的订阅节点不匹配")
	}
	if inbound != nil {
		if err := remote.VerifyDedicatedBinding(inbound, binding); err != nil {
			return err
		}
	}
	return nil
}

func (r *Repository) FinishServerChainDelete(profile, name, server string, id int) error {
	return r.UpdateState(profile, func(state Document) error {
		chain, err := namedServerChain(state, name)
		if err != nil {
			return err
		}
		if chain["serverId"] != server || !bindingInboundID(chain, id) {
			return errors.New("服务器链路归属已变化，请刷新")
		}
		keep := []any{}
		for _, item := range rows(state, "serverChains") {
			if item.(Document)["name"] != name {
				keep = append(keep, item)
			}
		}
		state["serverChains"] = keep
		return nil
	})
}
