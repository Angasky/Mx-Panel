package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Angasky/dingzhi-ban/templates"
	"go.yaml.in/yaml/v3"
)

var policyGroupFields = map[string]bool{"name": true, "type": true, "proxies": true, "url": true,
	"interval": true, "lazy": true, "tolerance": true, "strategy": true, "timeout": true,
	"max-failed-times": true, "expected-status": true}

func (r *Repository) blankProfile() (Document, error) {
	raw, err := os.ReadFile(filepath.Join(r.Root, "templates", "clash.yaml"))
	if os.IsNotExist(err) {
		raw = []byte(templates.Clash())
	} else if err != nil {
		return nil, err
	}
	var doc Document
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	if decoder.Decode(&doc) != nil || doc == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("内置模板损坏")
	}
	doc["proxies"] = []any{}
	return doc, validate(doc)
}

func policyGroupType(kind string) bool {
	return kind == "select" || kind == "url-test" || kind == "fallback" || kind == "load-balance"
}

func applyPolicyTemplate(doc, template Document) error {
	groups, groupsOK := template["groups"].([]any)
	rules, rulesOK := template["rules"].([]any)
	if !groupsOK || !rulesOK || len(groups) > 128 || len(rules) > 5000 {
		return errors.New("模板最多支持 128 个策略组和 5000 条规则")
	}
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true}
	for _, item := range groups {
		group, ok := item.(Document)
		if !ok {
			return errors.New("模板策略组格式无效")
		}
		for key := range group {
			if !policyGroupFields[key] {
				return fmt.Errorf("模板策略组不支持字段 %s", key)
			}
		}
		name := stringValue(group["name"])
		if name == "" || name != strings.TrimSpace(name) || known[name] || len([]rune(name)) > 120 ||
			strings.ContainsAny(name, ",\r\n\x00") || !policyGroupType(stringValue(group["type"])) || len(rows(group, "proxies")) == 0 {
			return errors.New("模板策略组必须有唯一名称、有效类型及成员")
		}
		known[name] = true
		if raw, exists := group["url"]; exists {
			address, err := url.Parse(stringValue(raw))
			if err != nil || address.Hostname() == "" || address.User != nil || (address.Scheme != "http" && address.Scheme != "https") {
				return errors.New("测速地址须为不含账号密码的 HTTP(S) 地址")
			}
		}
	}
	providers, _ := doc["rule-providers"].(Document)
	for i, item := range rules {
		raw, ok := item.(string)
		if !ok || len(raw) > 4096 || strings.ContainsAny(raw, "\r\n\x00") {
			return errors.New("模板规则必须为单行文本")
		}
		part := RuleParts(raw)
		if !known[stringValue(part["action"])] {
			return fmt.Errorf("第 %d 条规则引用了不存在的策略", i+1)
		}
		if part["type"] == "RULE-SET" && providers[stringValue(part["value"])] == nil {
			return fmt.Errorf("第 %d 条规则引用了不存在的规则集", i+1)
		}
		if (part["type"] == "MATCH") != (i == len(rules)-1) {
			return errors.New("模板需要一条位于最后的 MATCH 兜底规则")
		}
	}
	if len(rules) == 0 {
		return errors.New("模板需要一条位于最后的 MATCH 兜底规则")
	}
	omitted := map[string]bool{}
	for _, item := range rows(doc, "proxy-groups") {
		name := stringValue(item.(Document)["name"])
		omitted[name] = !known[name]
	}
	dns, _ := doc["dns"].(Document)
	policy, _ := dns["nameserver-policy"].(Document)
	fix := func(value any) any {
		raw, ok := value.(string)
		if i := strings.LastIndexByte(raw, '#'); ok && i >= 0 {
			name, err := url.PathUnescape(raw[i+1:])
			if err == nil && omitted[name] {
				return raw[:i] + "#DIRECT"
			}
		}
		return value
	}
	for key, value := range policy {
		if list, ok := value.([]any); ok {
			for i, item := range list {
				list[i] = fix(item)
			}
		} else {
			policy[key] = fix(value)
		}
	}
	doc["proxy-groups"], doc["rules"] = groups, rules
	return checkReferences(doc)
}

func policyTemplateSeed(base, current Document) Document {
	if current == nil {
		return Document{"groups": rows(base, "proxy-groups"), "rules": rows(base, "rules")}
	}
	groups := []any{}
	known := map[string]bool{"DIRECT": true, "REJECT": true, "REJECT-DROP": true, "PASS": true}
	for _, item := range rows(current, "proxy-groups") {
		original := item.(Document)
		kind := stringValue(original["type"])
		if !policyGroupType(kind) {
			continue
		}
		group := Document{}
		for key, value := range original {
			if policyGroupFields[key] && key != "url" {
				group[key] = value
			}
		}
		if kind != "select" {
			group["url"] = "https://www.gstatic.com/generate_204"
		}
		groups = append(groups, group)
		known[stringValue(group["name"])] = true
	}
	for _, item := range groups {
		group := item.(Document)
		members := []any{}
		for _, ref := range rows(group, "proxies") {
			if known[stringValue(ref)] {
				members = append(members, ref)
			}
		}
		if len(members) == 0 {
			members = append(members, "DIRECT")
		}
		group["proxies"] = members
	}
	rules, fallback := []any{}, "MATCH,DIRECT"
	providers, _ := base["rule-providers"].(Document)
	for _, item := range rows(current, "rules") {
		raw := item.(string)
		part := RuleParts(raw)
		if !known[stringValue(part["action"])] || (part["type"] == "RULE-SET" && providers[stringValue(part["value"])] == nil) {
			continue
		}
		if part["type"] == "MATCH" {
			fallback = raw
		} else {
			rules = append(rules, raw)
		}
	}
	return Document{"groups": groups, "rules": append(rules, fallback)}
}

func (r *Repository) PolicyTemplates(profileID, id, source string) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if id != "" || source == "" {
		index, err := r.index()
		if err != nil {
			return nil, err
		}
		list := []any{}
		for _, item := range rows(index, "policyTemplates") {
			record, ok := item.(Document)
			if !ok {
				return nil, errors.New("策略模板记录无效")
			}
			if id != "" && record["id"] == id {
				return Document{"template": record}, nil
			}
			list = append(list, Document{"id": record["id"], "name": record["name"]})
		}
		if id != "" {
			return nil, errors.New("策略模板不存在")
		}
		return Document{"templates": list}, nil
	}
	base, err := r.blankProfile()
	if err != nil {
		return nil, err
	}
	var current Document
	switch source {
	case "current":
		p, err := r.profile(profileID)
		if err != nil {
			return nil, err
		}
		current, _, err = r.cachedRead(p)
		if err != nil {
			return nil, err
		}
	case "default":
	default:
		return nil, errors.New("未知模板来源")
	}
	return Document{"template": policyTemplateSeed(base, current)}, nil
}

func (r *Repository) SavePolicyTemplate(method string, payload Document) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	list := rows(index, "policyTemplates")
	id := stringValue(payload["id"])
	if method == "POST" {
		id = ""
	}
	name := strings.TrimSpace(stringValue(payload["name"]))
	at := -1
	for i, item := range list {
		record, ok := item.(Document)
		if !ok {
			return nil, errors.New("策略模板记录无效")
		}
		if id != "" && record["id"] == id {
			at = i
		} else if method != "DELETE" && record["name"] == name {
			return nil, errors.New("模板名称已存在")
		}
	}
	if method != "POST" && at < 0 {
		return nil, errors.New("策略模板不存在")
	}
	var result Document
	if method == "DELETE" {
		list = append(list[:at], list[at+1:]...)
	} else {
		if name == "" || len([]rune(name)) > 60 || strings.ContainsAny(name, "\r\n\x00") {
			return nil, errors.New("模板名称不能为空或超过 60 字")
		}
		if method == "POST" {
			if len(list) >= 40 {
				return nil, errors.New("最多保存 40 个策略模板")
			}
			token, err := randomToken(12)
			if err != nil {
				return nil, err
			}
			id = "policy-" + token
		}
		result = Document{"id": id, "name": name, "groups": payload["groups"], "rules": payload["rules"]}
		raw, err := json.Marshal(result)
		if err != nil || len(raw) > 256<<10 {
			return nil, errors.New("单个模板最多 256 KB")
		}
		if err = normalizeNumbers(result); err != nil {
			return nil, err
		}
		base, err := r.blankProfile()
		if err != nil {
			return nil, err
		}
		if err := applyPolicyTemplate(base, result); err != nil {
			return nil, err
		}
		if method == "POST" {
			list = append(list, result)
		} else {
			list[at] = result
		}
	}
	index["policyTemplates"] = list
	if err := r.writeIndex(index); err != nil {
		return nil, err
	}
	return Document{"ok": true, "template": result}, nil
}
