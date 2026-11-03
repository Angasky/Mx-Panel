package config

import (
	"errors"
	"strings"

	"go.yaml.in/yaml/v3"
)

// EditChain copies the landing node's full protocol configuration. Shared nested
// maps must not let a subsequent edit alter the original landing node.
func EditChain(doc Document, method string, payload map[string]any, allowed []string) error {
	mode := stringValue(payload["mode"])
	if mode != "" && mode != "mihomo" {
		return errors.New("服务器端中转尚待迁移，请使用客户端链式代理")
	}
	if method != "POST" && method != "PUT" {
		return errors.New("链式代理操作无效")
	}
	name := strings.TrimSpace(stringValue(payload["name"]))
	entry, exit := stringValue(payload["entry"]), stringValue(payload["exit"])
	old := stringValue(payload["oldName"])
	if name == "" || entry == "" || exit == "" || entry == exit || name == entry || name == exit {
		return errors.New("请填写链路名称，并选择两个不同的普通节点")
	}
	var landing Document
	foundEntry := false
	for _, v := range rows(doc, "proxies") {
		node := v.(map[string]any)
		if node["name"] == entry || node["name"] == exit {
			if stringValue(node["dialer-proxy"]) != "" {
				return errors.New("入口和出口请选择普通节点，避免循环或多级链路")
			}
			if node["name"] == entry {
				foundEntry = true
			} else {
				landing = node
			}
		}
	}
	if !foundEntry || landing == nil {
		return errors.New("入口节点或出口节点不存在")
	}
	if method == "PUT" {
		found := false
		for _, v := range rows(doc, "proxies") {
			node := v.(map[string]any)
			if node["name"] == old && stringValue(node["dialer-proxy"]) != "" {
				found = true
			}
		}
		if !found {
			return errors.New("原链式代理不存在")
		}
	}
	data, err := yaml.Marshal(landing)
	if err != nil {
		return err
	}
	var chain Document
	if err = yaml.Unmarshal(data, &chain); err != nil {
		return err
	}
	chain["name"], chain["dialer-proxy"] = name, entry
	if err = EditNode(doc, method, Document{"oldName": old, "config": chain}); err != nil {
		return err
	}
	selected := payload["groups"]
	if selected == nil {
		values := []any{}
		for _, group := range allowed {
			values = append(values, group)
		}
		selected = values
	}
	return EditMembership(doc, Document{"name": name, "groups": selected}, allowed)
}
