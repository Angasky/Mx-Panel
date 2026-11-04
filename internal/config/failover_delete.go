package config

import "errors"

func findFailover(state Document, key, name string) (Document, error) {
	var found Document
	for _, item := range rows(state, key) {
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
	return found, nil
}

func draftCancelPaths(state, draft Document) (remaining []any, unsent []string, err error) {
	paths, entries, requests := rows(draft, "paths"), rows(draft, "entries"), rows(draft, "pathRequests")
	operation := stringValue(draft["requestId"])
	if draft["status"] != "creating" || operation == "" || len(paths) < 2 || len(paths) > 8 ||
		len(paths) != len(entries) || len(paths) != len(requests) {
		return nil, nil, errors.New("主备草稿的路径记录无效")
	}
	remaining = []any{}
	for i, path := range paths {
		request := FailoverPathRequest(operation, i)
		if stringValue(path) == "" || requests[i] != request {
			return nil, nil, errors.New("主备草稿的创建标识不匹配")
		}
		found := false
		for _, item := range rows(state, "serverChains") {
			chain, ok := item.(Document)
			if !ok {
				return nil, nil, errors.New("服务器链路记录无效")
			}
			if chain["name"] == path && chain["requestId"] == request && chain["entry"] == entries[i] && chain["exit"] == draft["exit"] {
				if found {
					return nil, nil, errors.New("主备草稿路径归属重复")
				}
				found = true
			}
		}
		if found {
			remaining = append(remaining, path)
		} else {
			unsent = append(unsent, request)
		}
	}
	return remaining, unsent, nil
}

func (r *Repository) FailoverDraftCancelPlan(profile, name string) (string, []string, error) {
	state, err := r.State(profile)
	if err != nil {
		return "", nil, err
	}
	draft, err := findFailover(state, "failoverDrafts", name)
	if err != nil || draft == nil {
		return "", nil, err
	}
	_, requests, err := draftCancelPaths(state, draft)
	return stringValue(draft["requestId"]), requests, err
}

// BeginFailoverDelete hides client-specific exports before detaching routing.
// It does not touch any remote resources until both changes are durable.
func (r *Repository) BeginFailoverDelete(profile, name, canceledDraft string) ([]string, error) {
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
	group, err := findFailover(state, "failovers", name)
	if err != nil {
		return nil, err
	}
	var draft Document
	if group == nil {
		draft, err = findFailover(state, "failoverDrafts", name)
		if err != nil {
			return nil, err
		}
		if draft == nil || canceledDraft == "" || draft["requestId"] != canceledDraft {
			return nil, errors.New("主备组不存在或草稿尚未核对")
		}
		group = draft
	}
	detachPaths := group["paths"]
	if group["detachPaths"] != nil {
		detachPaths = group["detachPaths"]
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
			if row["type"] != "fallback" || !equalConfig(row["proxies"], detachPaths) {
				return errors.New("主备组配置与登记的路径不一致，未修改配置")
			}
		}
		doc["proxy-groups"] = groups
		replaceReferences(doc, name, "REJECT")
		return checkReferences(doc)
	}
	if group["status"] == "active" || group["status"] == "creating" {
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
	}
	switch group["status"] {
	case "creating":
		if draft == nil {
			return nil, errors.New("主备组没有可取消的草稿")
		}
		remaining, _, err := draftCancelPaths(state, draft)
		if err != nil {
			return nil, err
		}
		paths = paths[:0]
		for _, path := range remaining {
			paths = append(paths, stringValue(path))
		}
		group["status"], group["paths"], group["detachPaths"] = "deleting", remaining, detachPaths
		keep := []any{}
		for _, item := range rows(state, "failoverDrafts") {
			if item.(Document)["name"] != name {
				keep = append(keep, item)
			}
		}
		state["failoverDrafts"] = keep
		state["failovers"] = append(rows(state, "failovers"), group)
		if err := r.writeIndex(index); err != nil {
			return nil, err
		}
	case "active":
		if len(paths) < 2 || len(paths) > 8 {
			return nil, errors.New("有效主备组路径数量无效")
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
		group, err := findFailover(state, "failovers", name)
		if err != nil {
			return err
		}
		if group == nil || group["status"] != "deleting" || len(rows(group, "paths")) != 0 {
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
