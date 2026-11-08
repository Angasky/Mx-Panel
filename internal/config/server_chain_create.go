package config

import (
	"encoding/hex"
	"errors"
	"slices"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

type ServerChainImport struct {
	Name, Entry, Exit, Request string
	Groups                     any
}

func (r *Repository) ServerChainSources(id string, chain *ServerChainImport) (Document, Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	decoded, err := hex.DecodeString(chain.Request)
	if err != nil || len(decoded) != 16 || len(chain.Request) != 32 {
		return nil, nil, errors.New("缺少有效的链路创建标识")
	}
	if chain.Name == "" || len([]rune(chain.Name)) > 100 || strings.ContainsAny(chain.Name, "\r\n\x00,") ||
		chain.Entry == chain.Exit || chain.Name == chain.Entry || chain.Name == chain.Exit ||
		slices.Contains([]string{"DIRECT", "REJECT", "REJECT-DROP", "PASS"}, chain.Name) {
		return nil, nil, errors.New("请填写有效的链路名称，并选择两个不同的普通节点")
	}
	index, err := r.index()
	if err != nil {
		return nil, nil, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return nil, nil, err
	}
	for _, raw := range rows(record, "failoverDrafts") {
		draft := raw.(Document)
		if draft["cancelRequested"] == true {
			for _, request := range rows(draft, "pathRequests") {
				if request == chain.Request {
					return nil, nil, errors.New("此主备路径正在取消，不能继续创建")
				}
			}
		}
	}
	p, err := profileFrom(record)
	if err != nil {
		return nil, nil, err
	}
	doc, _, err := r.cachedRead(p)
	if err != nil {
		return nil, nil, err
	}
	if err := validateChainGroups(chain, groupOptions(doc, p)); err != nil {
		return nil, nil, err
	}
	for _, item := range rows(record, "serverChains") {
		stored, ok := item.(Document)
		if !ok {
			return nil, nil, errors.New("服务器链路记录无效")
		}
		if stored["name"] == chain.Entry || stored["name"] == chain.Exit {
			return nil, nil, errors.New("入口和出口请选择普通节点")
		}
		if stored["name"] == chain.Name &&
			(stored["requestId"] != chain.Request || stored["entry"] != chain.Entry || stored["exit"] != chain.Exit) {
			return nil, nil, errors.New("同名链路已存在")
		}
	}
	for _, item := range rows(doc, "proxy-groups") {
		if item.(Document)["name"] == chain.Name {
			return nil, nil, errors.New("链路名称与现有策略组冲突")
		}
	}
	var entry, exit Document
	for _, item := range rows(doc, "proxies") {
		node := item.(Document)
		switch node["name"] {
		case chain.Entry, chain.Exit:
			if stringValue(node["dialer-proxy"]) != "" {
				return nil, nil, errors.New("入口和出口请选择普通节点")
			}
			if node["name"] == chain.Entry {
				entry = node
			} else {
				exit = node
			}
		case chain.Name:
			owned := false
			for _, item := range rows(record, "remoteNodes") {
				binding := item.(Document)
				if binding["chainRequest"] == chain.Request && managednodes.Owns(binding, node) {
					owned = true
					break
				}
			}
			if !owned {
				return nil, nil, errors.New("链路名称与现有节点冲突")
			}
		}
	}
	if entry == nil || exit == nil {
		return nil, nil, errors.New("入口或出口节点不存在")
	}
	return cloneConfig(entry).(Document), cloneConfig(exit).(Document), nil
}

func validateChainGroups(chain *ServerChainImport, allowed []string) error {
	groups, ok := chain.Groups.([]any)
	if !ok {
		return errors.New("策略组列表无效")
	}
	for _, group := range groups {
		if !slices.Contains(allowed, stringValue(group)) {
			return errors.New("所选策略组已变化，请刷新后再试")
		}
	}
	return nil
}

func prepareNamedChainRecord(record, binding Document, chain *ServerChainImport) ([]any, error) {
	if binding["chainRequest"] != chain.Request {
		return nil, errors.New("中转用户归属不属于此链路请求")
	}
	records := rows(record, "serverChains")
	for _, item := range records {
		current, ok := item.(Document)
		if !ok {
			return nil, errors.New("服务器链路记录无效")
		}
		if current["name"] == chain.Name {
			id, err := integer(binding["inboundId"])
			if err != nil || !bindingInboundID(current, id) || current["serverId"] != binding["serverId"] ||
				current["requestId"] != chain.Request || current["entry"] != chain.Entry || current["exit"] != chain.Exit {
				return nil, errors.New("同名服务器链路归属已变化")
			}
			return records, nil
		}
	}
	return append(records, Document{"name": chain.Name, "entry": chain.Entry, "exit": chain.Exit,
		"requestId": chain.Request, "serverId": binding["serverId"], "inboundId": binding["inboundId"]}), nil
}
