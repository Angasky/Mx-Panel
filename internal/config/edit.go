package config

import (
	"errors"
	"io"
	"strings"

	"go.yaml.in/yaml/v3"
)

func RuleParts(raw string) map[string]any {
	result := map[string]any{"raw": raw, "type": "RAW", "value": raw, "action": "", "options": ""}
	parts := strings.Split(raw, ",")
	if len(parts) == 2 && parts[0] == "MATCH" {
		result["type"] = "MATCH"
		result["value"] = ""
		result["action"] = parts[1]
		return result
	}
	if len(parts) < 3 {
		return result
	}
	action := len(parts) - 1
	if len(parts) >= 4 && (parts[action] == "no-resolve" || parts[action] == "src") {
		action--
	}
	result["type"] = parts[0]
	result["value"] = strings.Join(parts[1:action], ",")
	result["action"] = parts[action]
	result["options"] = strings.Join(parts[action+1:], ",")
	return result
}
func buildRule(payload map[string]any) (string, error) {
	if payload["rawMode"] == true {
		raw := strings.TrimSpace(stringValue(payload["raw"]))
		if raw == "" || strings.ContainsAny(raw, "\r\n\x00") {
			return "", errors.New("原始规则不能为空或包含换行")
		}
		return raw, nil
	}
	kind := strings.ToUpper(strings.TrimSpace(stringValue(payload["type"])))
	if kind == "" {
		kind = "DOMAIN-SUFFIX"
	}
	value := strings.TrimSpace(stringValue(payload["value"]))
	action := strings.TrimSpace(stringValue(payload["action"]))
	if action == "" {
		action = "DIRECT"
	}
	options := strings.Trim(strings.TrimSpace(stringValue(payload["options"])), ",")
	if strings.ContainsAny(kind+value+action+options, "\r\n\x00") {
		return "", errors.New("规则不能包含换行")
	}
	if kind == "MATCH" {
		return "MATCH," + action, nil
	}
	if value == "" {
		return "", errors.New("规则匹配值不能为空")
	}
	rule := kind + "," + value + "," + action
	if options != "" {
		rule += "," + options
	}
	return rule, nil
}
func EditRule(doc Document, method string, payload map[string]any) error {
	list := rows(doc, "rules")
	old := stringValue(payload["oldRaw"])
	index := -1
	for i, item := range list {
		if item == old {
			index = i
			break
		}
	}
	if method == "DELETE" {
		if index < 0 {
			return errors.New("规则不存在")
		}
		doc["rules"] = append(list[:index], list[index+1:]...)
		return nil
	}
	raw, err := buildRule(payload)
	if err != nil {
		return err
	}
	if method == "POST" {
		at := 0
		if payload["index"] != nil {
			at, err = integer(payload["index"])
			if err != nil {
				return err
			}
		}
		if at < 0 {
			at = 0
		}
		if at > len(list) {
			at = len(list)
		}
		list = append(list, nil)
		copy(list[at+1:], list[at:])
		list[at] = raw
	} else {
		if index < 0 {
			return errors.New("原规则不存在")
		}
		list[index] = raw
	}
	doc["rules"] = list
	return nil
}
func MoveRule(doc Document, payload map[string]any) error {
	list := rows(doc, "rules")
	index := -1
	for i, v := range list {
		if v == payload["raw"] {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("规则不存在")
	}
	direction, err := integer(payload["direction"])
	if err != nil || direction != 1 && direction != -1 {
		return errors.New("移动方向无效")
	}
	at := index + direction
	if at < 0 || at >= len(list) {
		return nil
	}
	list[index], list[at] = list[at], list[index]
	doc["rules"] = list
	return nil
}
func EditGroup(doc Document, method string, payload map[string]any) error {
	list := rows(doc, "proxy-groups")
	old := stringValue(payload["oldName"])
	if method == "DELETE" {
		old = stringValue(payload["name"])
	}
	index := -1
	for i, v := range list {
		if v.(map[string]any)["name"] == old {
			index = i
			break
		}
	}
	if method == "DELETE" {
		if old == "✈️ Proxy" {
			return errors.New("主 Proxy 策略组不能删除")
		}
		if index < 0 {
			return errors.New("策略组不存在")
		}
		doc["proxy-groups"] = append(list[:index], list[index+1:]...)
		replaceReferences(doc, old, "")
		return nil
	}
	group, ok := payload["config"].(map[string]any)
	if !ok {
		return errors.New("策略组配置必须为对象")
	}
	if err := normalizeNumbers(group); err != nil {
		return err
	}
	name := strings.TrimSpace(stringValue(group["name"]))
	kind := stringValue(group["type"])
	if name == "" || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("策略组名称无效")
	}
	if kind != "select" && kind != "url-test" && kind != "fallback" && kind != "load-balance" && kind != "relay" {
		return errors.New("策略组类型无效")
	}
	refs, ok := group["proxies"].([]any)
	providers, _ := group["use"].([]any)
	if !ok && len(providers) == 0 || len(refs) == 0 && len(providers) == 0 {
		return errors.New("策略组必须包含节点、策略组或提供者")
	}
	for _, ref := range refs {
		if _, ok := ref.(string); !ok {
			return errors.New("策略组成员必须为名称")
		}
		if ref == name {
			return errors.New("策略组不能包含自身")
		}
	}
	group["name"] = name
	if method == "POST" {
		doc["proxy-groups"] = append(list, group)
	} else {
		if index < 0 {
			return errors.New("原策略组不存在")
		}
		list[index] = group
		doc["proxy-groups"] = list
		if old != name {
			replaceReferences(doc, old, name)
		}
	}
	return checkReferences(doc)
}
func EditDNS(doc Document, method string, payload map[string]any) error {
	dns, ok := doc["dns"].(map[string]any)
	if !ok {
		dns = map[string]any{}
		doc["dns"] = dns
	}
	policy, ok := dns["nameserver-policy"].(map[string]any)
	if !ok {
		policy = map[string]any{}
		dns["nameserver-policy"] = policy
	}
	old := stringValue(payload["oldDomain"])
	if method == "DELETE" {
		if _, ok := policy[old]; !ok {
			return errors.New("DNS 分流规则不存在")
		}
		delete(policy, old)
		return nil
	}
	domain := strings.TrimSpace(stringValue(payload["domain"]))
	if domain == "" || strings.ContainsAny(domain, "\r\n\x00") {
		return errors.New("DNS 域名无效")
	}
	servers, ok := payload["servers"].([]any)
	if text, isText := payload["servers"].(string); isText {
		servers = []any{}
		for _, line := range strings.Split(text, "\n") {
			if value := strings.TrimSpace(line); value != "" {
				servers = append(servers, value)
			}
		}
		ok = true
	}
	if !ok || len(servers) == 0 {
		return errors.New("DNS 服务器不能为空")
	}
	for _, value := range servers {
		if text, ok := value.(string); !ok || strings.TrimSpace(text) == "" || strings.ContainsAny(text, "\r\n\x00") {
			return errors.New("DNS 服务器格式无效")
		}
	}
	if old != "" && old != domain {
		delete(policy, old)
	}
	policy[domain] = servers
	return nil
}
func ReplaceRaw(doc Document, payload map[string]any) error {
	text := stringValue(payload["yaml"])
	if text == "" || len(text) > 8<<20 {
		return errors.New("YAML 为空或超过大小限制")
	}
	var next Document
	decoder := yaml.NewDecoder(strings.NewReader(text))
	if err := decoder.Decode(&next); err != nil || next == nil {
		return errors.New("YAML 配置无效")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("不支持多个 YAML 文档")
	}
	if err := validate(next); err != nil {
		return err
	}
	if err := checkReferences(next); err != nil {
		return err
	}
	for key := range doc {
		delete(doc, key)
	}
	for key, value := range next {
		doc[key] = value
	}
	return nil
}
func checkReferences(doc Document) error {
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true}
	groups := map[string]map[string]any{}
	for _, key := range []string{"proxies", "proxy-groups"} {
		for _, value := range rows(doc, key) {
			row := value.(map[string]any)
			name := stringValue(row["name"])
			if known[name] {
				return errors.New("名称重复或与内置动作冲突")
			}
			known[name] = true
			if key == "proxy-groups" {
				groups[name] = row
			}
		}
	}
	for _, group := range groups {
		refs, _ := group["proxies"].([]any)
		for _, ref := range refs {
			name, ok := ref.(string)
			if !ok || !known[name] {
				return errors.New("策略组引用了不存在的节点或策略组")
			}
		}
	}
	state := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if state[name] == 1 {
			return false
		}
		if state[name] == 2 {
			return true
		}
		state[name] = 1
		refs, _ := groups[name]["proxies"].([]any)
		for _, ref := range refs {
			child := stringValue(ref)
			if groups[child] != nil && !visit(child) {
				return false
			}
		}
		state[name] = 2
		return true
	}
	for name := range groups {
		if !visit(name) {
			return errors.New("策略组存在循环引用")
		}
	}
	for _, value := range rows(doc, "rules") {
		parts := RuleParts(value.(string))
		action := stringValue(parts["action"])
		if action != "" && !known[action] {
			return errors.New("路由规则引用了不存在的动作")
		}
	}
	return nil
}
