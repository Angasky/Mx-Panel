package config

import (
	"errors"
	"regexp"
	"slices"
	"strings"
)

var groupDomain = regexp.MustCompile(`^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$`)
var groupRuleKind = regexp.MustCompile(`^[A-Z][A-Z0-9-]*$`)

func scopedGroupRule(raw any, name string) (string, error) {
	line, ok := raw.(string)
	if !ok || len(line) > 4096 || strings.ContainsAny(line, "\r\n\x00") {
		return "", errors.New("分流规则必须是一行文本")
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return "", nil
	}
	kind, value, hasType := strings.Cut(line, ",")
	if !hasType {
		if len(line) > 253 || !groupDomain.MatchString(line) {
			return "", errors.New("请输入域名，或使用 DOMAIN-SUFFIX,域名 格式")
		}
		kind, value = "DOMAIN-SUFFIX", line
	}
	kind = strings.ToUpper(strings.TrimSpace(kind))
	if !groupRuleKind.MatchString(kind) || kind == "MATCH" || kind == "RAW" {
		return "", errors.New("规则类型无效，MATCH 请在分流规则页编辑")
	}
	var options string
	for _, option := range []string{"no-resolve", "src"} {
		if trimmed, ok := strings.CutSuffix(value, ","+option); ok {
			value, options = trimmed, option
			break
		}
	}
	return buildRule(Document{"type": kind, "value": value, "action": name, "options": options})
}

func matchesGroupRule(raw, name string) bool {
	part := RuleParts(raw)
	return part["type"] != "MATCH" && part["action"] == name
}

func prepareGroupRules(doc, payload Document, old, name string) ([]string, error) {
	input, ok := payload["groupRules"].([]any)
	if !ok || len(input) > 2000 || strings.ContainsRune(name, ',') {
		return nil, errors.New("策略组规则格式无效，最多 2000 条，组名不能含逗号")
	}
	expected, _ := payload["expectedGroupRules"].([]any)
	current := []any{}
	if old != "" {
		for _, item := range rows(doc, "rules") {
			if matchesGroupRule(item.(string), old) {
				current = append(current, item)
			}
		}
	}
	if !slices.EqualFunc(expected, current, func(a, b any) bool {
		raw, ok := a.(string)
		return ok && raw == b
	}) {
		return nil, errors.New("策略组的分流规则已变化，请刷新后再编辑")
	}
	providers, _ := doc["rule-providers"].(Document)
	result, seen := []string{}, map[string]bool{}
	for _, item := range input {
		rule, err := scopedGroupRule(item, name)
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(rule, "RULE-SET,") && providers[stringValue(RuleParts(rule)["value"])] == nil {
			return nil, errors.New("策略组规则引用了不存在的规则集")
		}
		if rule != "" && !seen[rule] {
			seen[rule] = true
			result = append(result, rule)
		}
	}
	return result, nil
}

func replaceGroupRules(doc Document, name string, replacements []string) {
	updated := []any{}
	position, consumed := 0, 0
	for _, item := range rows(doc, "rules") {
		if matchesGroupRule(item.(string), name) {
			if consumed < len(replacements) {
				updated = append(updated, replacements[consumed])
				consumed++
			}
			position = len(updated)
		} else {
			updated = append(updated, item)
		}
	}
	extra := make([]any, 0, len(replacements)-consumed)
	for _, raw := range replacements[consumed:] {
		extra = append(extra, raw)
	}
	doc["rules"] = slices.Insert(updated, position, extra...)
}
