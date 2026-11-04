package config

import (
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func namedServerChain(record Document, name, deletingGroup string) (Document, error) {
	var parent Document
	for _, item := range append(append([]any{}, rows(record, "failovers")...), rows(record, "failoverDrafts")...) {
		f, ok := item.(Document)
		if !ok {
			return nil, errors.New("主备归属记录无效")
		}
		if f["name"] == name {
			return nil, errors.New("该链路由主备组管理")
		}
		for _, path := range rows(f, "paths") {
			if path == name {
				if deletingGroup == "" || f["name"] != deletingGroup || f["status"] != "deleting" {
					return nil, errors.New("该链路由主备组管理")
				}
				parent = f
			}
		}
	}
	if deletingGroup != "" && parent == nil {
		return nil, errors.New("链路不属于待删除主备组")
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
	if parent != nil {
		if result["exit"] != parent["exit"] {
			return nil, errors.New("链路出口与主备组归属不一致")
		}
		if operation := stringValue(parent["requestId"]); operation != "" {
			matched := false
			for i, entry := range rows(parent, "entries") {
				if entry == result["entry"] && result["requestId"] == FailoverPathRequest(operation, i) {
					matched = true
					break
				}
			}
			if !matched {
				return nil, errors.New("链路创建记录与主备组归属不一致")
			}
		}
	}
	return result, nil
}

func (r *Repository) ServerChainTarget(profile, name string) (string, int, error) {
	return r.ServerChainDeleteTarget(profile, name, "")
}

func (r *Repository) ServerChainDeleteTarget(profile, name, deletingGroup string) (string, int, error) {
	state, err := r.State(profile)
	if err != nil {
		return "", 0, err
	}
	chain, err := namedServerChain(state, name, deletingGroup)
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

func (r *Repository) BeginServerChainDelete(profile, name, server string, id int, inbound Document, deletingGroup, expected string, observed map[string]bool) error {
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
	chain, err := namedServerChain(record, name, deletingGroup)
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
			if owner["id"] != record["id"] || (!active && candidate["status"] != "missing" && candidate["status"] != "revoked") {
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
	if request := stringValue(chain["requestId"]); request != "" && binding["chainRequest"] != request {
		return errors.New("链路与订阅绑定的创建记录不一致")
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
		if err := remote.VerifyDedicatedBinding(inbound, binding, binding["status"] == "revoked" || binding["status"] == "missing"); err != nil {
			return err
		}
	}
	if !observed[BindingToken(stringValue(record["id"]), binding)] {
		return errors.New("订阅绑定代次已变化，请刷新")
	}
	binding["inboundDeletePending"] = Document{"expected": expected, "at": time.Now().Unix()}
	return r.writeIndex(index)
}

func (r *Repository) FinishServerChainDelete(profile, name, server string, id int, deletingGroup string) error {
	return r.UpdateState(profile, func(state Document) error {
		chain, err := namedServerChain(state, name, deletingGroup)
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
		if deletingGroup != "" {
			for _, item := range rows(state, "failovers") {
				group := item.(Document)
				if group["name"] == deletingGroup && group["status"] == "deleting" {
					paths := []any{}
					for _, path := range rows(group, "paths") {
						if path != name {
							paths = append(paths, path)
						}
					}
					group["paths"] = paths
				}
			}
		}
		return nil
	})
}
