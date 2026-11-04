package config

import "errors"

func failoverRecord(state Document, name string) (Document, error) {
	var found Document
	for _, item := range rows(state, "failovers") {
		row, ok := item.(Document)
		if !ok {
			return nil, errors.New("主备记录无效")
		}
		if row["name"] == name {
			if found != nil {
				return nil, errors.New("主备组名称重复")
			}
			found = row
		}
	}
	if found == nil {
		return nil, errors.New("有效主备组不存在")
	}
	return found, nil
}

// BeginFailoverDelete hides client-specific exports before detaching routing.
// It does not touch any remote resources until both changes are durable.
func (r *Repository) BeginFailoverDelete(profile, name string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	state, err := stateRecord(index, profile)
	if err != nil {
		return nil, err
	}
	group, err := failoverRecord(state, name)
	if err != nil {
		return nil, err
	}
	paths := []string{}
	seen := map[string]bool{}
	for _, raw := range rows(group, "paths") {
		path := stringValue(raw)
		if path == "" || path == name || seen[path] {
			return nil, errors.New("主备路径记录无效")
		}
		seen[path] = true
		paths = append(paths, path)
	}
	detach := func(doc Document) error {
		for _, item := range rows(doc, "proxies") {
			if item.(Document)["name"] == name {
				return errors.New("同名节点与主备组冲突")
			}
		}
		groups := []any{}
		for _, item := range rows(doc, "proxy-groups") {
			row := item.(Document)
			if row["name"] != name {
				groups = append(groups, row)
				continue
			}
			if row["type"] != "fallback" || !equalConfig(row["proxies"], group["paths"]) {
				return errors.New("主备组配置与登记的路径不一致，未修改配置")
			}
		}
		doc["proxy-groups"] = groups
		replaceReferences(doc, name, "REJECT")
		return checkReferences(doc)
	}
	switch group["status"] {
	case "active":
		if len(paths) < 2 || len(paths) > 8 {
			return nil, errors.New("有效主备组路径数量无效")
		}
		profileConfig, err := profileFrom(state)
		if err != nil {
			return nil, err
		}
		doc, _, err := r.cachedRead(profileConfig)
		if err != nil {
			return nil, err
		}
		if err := detach(cloneConfig(doc).(Document)); err != nil {
			return nil, err
		}
		group["status"] = "deleting"
		if err := r.writeIndex(index); err != nil {
			return nil, err
		}
	case "deleting":
	default:
		return nil, errors.New("该主备组尚未完成创建，不能从此入口删除")
	}
	if err := r.mutateGuardedLocked(profile, detach, false); err != nil {
		return nil, err
	}
	return paths, nil
}

func (r *Repository) FinishFailoverDelete(profile, name string) error {
	return r.UpdateState(profile, func(state Document) error {
		group, err := failoverRecord(state, name)
		if err != nil {
			return err
		}
		if group["status"] != "deleting" || len(rows(group, "paths")) != 0 {
			return errors.New("主备组还有待清理路径")
		}
		keep := []any{}
		for _, item := range rows(state, "failovers") {
			if item.(Document)["name"] != name {
				keep = append(keep, item)
			}
		}
		state["failovers"] = keep
		return nil
	})
}
