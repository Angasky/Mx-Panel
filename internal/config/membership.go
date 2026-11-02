package config

import "errors"

var excludedNodeGroups = map[string]bool{"🛑 广告拦截": true, "🛡️ 基础广告拦截": true, "🔥 强力广告拦截": true}

func (r *Repository) GroupOptions(id string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	doc, _, err := read(p)
	if err != nil {
		return nil, err
	}
	blocked := map[string]bool{}
	for name := range excludedNodeGroups {
		blocked[name] = true
	}
	for _, failover := range p.Failovers {
		blocked[stringValue(failover["name"])] = true
	}
	result := []string{}
	for _, value := range rows(doc, "proxy-groups") {
		name := stringValue(value.(map[string]any)["name"])
		if !blocked[name] {
			result = append(result, name)
		}
	}
	return result, nil
}

func EditMembership(doc Document, payload map[string]any, allowed []string) error {
	name := stringValue(payload["name"])
	exists := false
	for _, value := range rows(doc, "proxies") {
		if value.(map[string]any)["name"] == name {
			exists = true
			break
		}
	}
	if !exists {
		return errors.New("节点不存在，请刷新")
	}
	input, ok := payload["groups"].([]any)
	if !ok {
		return errors.New("请选择策略组")
	}
	available := map[string]bool{}
	for _, name := range allowed {
		available[name] = true
	}
	selected := map[string]bool{}
	for _, value := range input {
		group, ok := value.(string)
		if !ok || !available[group] {
			return errors.New("策略组已变化，请刷新后重试")
		}
		selected[group] = true
	}
	for _, value := range rows(doc, "proxy-groups") {
		group := value.(map[string]any)
		groupName := stringValue(group["name"])
		if !available[groupName] {
			continue
		}
		refs, _ := group["proxies"].([]any)
		next := []any{}
		present := false
		for _, ref := range refs {
			if ref == name {
				present = true
				if !selected[groupName] {
					continue
				}
			}
			next = append(next, ref)
		}
		if selected[groupName] && !present {
			next = append(next, name)
		}
		providers, _ := group["use"].([]any)
		if len(next) == 0 && len(providers) == 0 {
			return errors.New("移除后策略组为空，请先添加其他节点")
		}
		group["proxies"] = next
	}
	return nil
}

func DeleteManyNodes(doc Document, payload map[string]any) error {
	input, ok := payload["names"].([]any)
	if !ok || len(input) == 0 {
		return errors.New("请选择节点")
	}
	names := map[string]bool{}
	for _, value := range input {
		name, ok := value.(string)
		if !ok {
			return errors.New("节点名称无效")
		}
		names[name] = true
	}
	for name := range names {
		// References from another node being deleted can be removed in this batch;
		// references from retained chain nodes must fail the whole transaction.
		for _, value := range rows(doc, "proxies") {
			node := value.(map[string]any)
			if node["dialer-proxy"] == name && !names[stringValue(node["name"])] {
				return errors.New("节点仍被链式代理引用，请先移除链路")
			}
		}
	}
	existing := map[string]bool{}
	next := []any{}
	for _, value := range rows(doc, "proxies") {
		name := stringValue(value.(map[string]any)["name"])
		existing[name] = true
		if !names[name] {
			next = append(next, value)
		}
	}
	for name := range names {
		if !existing[name] {
			return errors.New("部分节点已不存在，请刷新")
		}
	}
	doc["proxies"] = next
	for name := range names {
		replaceReferences(doc, name, "")
	}
	return nil
}
