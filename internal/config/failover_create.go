package config

import (
	"errors"
	"fmt"
	"slices"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

func (r *Repository) BeginFailover(profile string, plan Document) error {
	return r.UpdateState(profile, func(p Document) error {
		for _, key := range []string{"failovers", "failoverDrafts"} {
			for _, item := range rows(p, key) {
				row, ok := item.(Document)
				if !ok {
					return errors.New("主备记录无效")
				}
				if row["name"] == plan["name"] {
					if row["requestId"] == plan["requestId"] && row["requestHash"] == plan["requestHash"] {
						return nil
					}
					return errors.New("同名主备任务已存在")
				}
				if row["requestId"] == plan["requestId"] {
					return errors.New("主备请求标识已被使用")
				}
			}
		}
		profileConfig, err := profileFrom(p)
		if err != nil {
			return err
		}
		doc, _, err := r.cachedRead(profileConfig)
		if err != nil {
			return err
		}
		for _, key := range []string{"proxies", "proxy-groups"} {
			for _, item := range rows(doc, key) {
				if item.(Document)["name"] == plan["name"] {
					return errors.New("主备组名称与现有节点或策略组冲突")
				}
			}
		}
		if err := validateChainGroups(&ServerChainImport{Groups: plan["groups"]}, groupOptions(doc, profileConfig)); err != nil {
			return err
		}
		p["failoverDrafts"] = append(rows(p, "failoverDrafts"), plan)
		return nil
	})
}

func (r *Repository) ActivateFailover(profile string, plan Document) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	record, err := stateRecord(index, profile)
	if err != nil {
		return nil, err
	}
	for _, item := range rows(record, "failovers") {
		row, ok := item.(Document)
		if ok && row["name"] == plan["name"] && row["requestId"] == plan["requestId"] {
			return row, nil
		}
	}
	drafts := []any{}
	found := false
	for _, item := range rows(record, "failoverDrafts") {
		row, ok := item.(Document)
		if ok && row["name"] == plan["name"] && row["requestId"] == plan["requestId"] && row["requestHash"] == plan["requestHash"] {
			found = true
		} else {
			drafts = append(drafts, item)
		}
	}
	if !found {
		return nil, errors.New("主备任务归属已变化")
	}
	paths, entries := rows(plan, "paths"), rows(plan, "entries")
	requests := rows(plan, "pathRequests")
	if len(paths) < 2 || len(paths) != len(entries) || len(paths) != len(requests) {
		return nil, errors.New("主备路径计划格式无效")
	}
	profileConfig, err := profileFrom(record)
	if err != nil {
		return nil, err
	}
	active := Document{"name": plan["name"], "paths": paths, "entries": entries, "exit": plan["exit"],
		"interval": plan["interval"], "status": "active", "requestId": plan["requestId"], "requestHash": plan["requestHash"]}
	err = r.mutateLocked(profile, func(doc Document) error {
		for i, path := range paths {
			var chain, node Document
			for _, item := range rows(record, "serverChains") {
				row := item.(Document)
				if row["name"] == path && row["exit"] == plan["exit"] && row["entry"] == entries[i] && row["requestId"] == requests[i] {
					chain = row
					break
				}
			}
			for _, item := range rows(doc, "proxies") {
				row := item.(Document)
				if row["name"] == path && stringValue(row["dialer-proxy"]) == "" {
					node = row
					break
				}
			}
			owned := false
			for _, item := range rows(record, "remoteNodes") {
				binding := item.(Document)
				if chain != nil && node != nil && binding["serverId"] == chain["serverId"] &&
					fmt.Sprint(binding["inboundId"]) == fmt.Sprint(chain["inboundId"]) &&
					binding["status"] == "active" && binding["monthlyPaused"] != true &&
					binding["inboundDeletePending"] == nil && binding["chainRequest"] == requests[i] && managednodes.Owns(binding, node) {
					owned = true
					break
				}
			}
			if !owned {
				return fmt.Errorf("主备路径 %s 尚未确认", path)
			}
		}
		group := Document{"name": plan["name"], "type": "fallback", "proxies": paths,
			"url": "https://www.gstatic.com/generate_204", "interval": plan["interval"], "timeout": 5000,
			"lazy": false, "max-failed-times": 1}
		for _, item := range rows(doc, "proxies") {
			if item.(Document)["name"] == group["name"] {
				return errors.New("主备组名称与现有节点冲突")
			}
		}
		allowed := groupOptions(doc, profileConfig)
		selected := map[string]bool{}
		for _, name := range rows(plan, "groups") {
			groupName := stringValue(name)
			valid := false
			for _, candidate := range allowed {
				if candidate == groupName && candidate != group["name"] {
					valid = true
					break
				}
			}
			if !valid {
				return errors.New("所选业务策略组已变化")
			}
			selected[groupName] = true
		}
		exists := false
		for _, item := range rows(doc, "proxy-groups") {
			row := item.(Document)
			if row["name"] == group["name"] {
				if !equalConfig(row, group) {
					return errors.New("同名策略组已存在")
				}
				exists = true
			} else if selected[stringValue(row["name"])] {
				refs := rows(row, "proxies")
				if !slices.Contains(refs, group["name"]) {
					row["proxies"] = append(refs, group["name"])
				}
			}
		}
		if !exists {
			doc["proxy-groups"] = append(rows(doc, "proxy-groups"), group)
		}
		return checkReferences(doc)
	})
	if err != nil {
		return nil, err
	}
	record["failoverDrafts"] = drafts
	record["failovers"] = append(rows(record, "failovers"), active)
	if err := r.writeIndex(index); err != nil {
		return nil, errors.New("主备组配置已写入，状态待重试确认")
	}
	return active, nil
}
