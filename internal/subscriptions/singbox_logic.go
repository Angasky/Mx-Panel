package subscriptions

import (
	"errors"
	"strings"
)

// Split commas at the current nesting level only. Bounds apply before recursion.
func splitRoutingParts(raw string) ([]string, error) {
	if len(raw) == 0 || len(raw) > 8192 {
		return nil, errors.New("规则长度无效")
	}
	depth, start := 0, 0
	parts := []string{}
	for i, ch := range raw {
		switch ch {
		case '(':
			depth++
			if depth > 16 {
				return nil, errors.New("逻辑嵌套过深")
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, errors.New("括号不匹配")
			}
		case ',':
			if depth == 0 {
				parts = append(parts, raw[start:i])
				start = i + 1
			}
		}
	}
	if depth != 0 {
		return nil, errors.New("括号不匹配")
	}
	parts = append(parts, raw[start:])
	return parts, nil
}
func singBoxCondition(kind, value string, noResolve bool, depth int, count *int, sets ...map[string]routingRuleSet) (Record, error) {
	*count++
	if depth > 8 || *count > 128 {
		return nil, errors.New("逻辑规则最多 8 层、128 个条件")
	}
	if kind == "RULE-SET" {
		if len(sets) == 0 {
			return nil, errors.New("规则集内部不支持 RULE-SET 嵌套引用")
		}
		set, ok := sets[0][value]
		if !ok {
			return nil, errors.New("引用的内嵌规则集不存在")
		}
		if set.RequiresNoResolve && !noResolve {
			return nil, errors.New("包含目标 IP 的规则集引用需要显式 no-resolve")
		}
		return Record{"rule_set": []string{set.Tag}}, nil
	}
	if kind != "AND" && kind != "OR" && kind != "NOT" {
		return singBoxBasicCondition(kind, value, noResolve)
	}
	if noResolve {
		return nil, errors.New("逻辑规则不接受顶层 no-resolve，请在 IP 子条件明确设置")
	}
	if len(value) < 2 || value[0] != '(' || value[len(value)-1] != ')' {
		return nil, errors.New("逻辑条件需要括号")
	}
	children, err := splitRoutingParts(value[1 : len(value)-1])
	if err != nil {
		return nil, err
	}
	if kind == "NOT" && len(children) != 1 {
		return nil, errors.New("NOT 必须有且仅有一个条件")
	}
	if kind != "NOT" && len(children) < 2 {
		return nil, errors.New("AND/OR 至少需要两个条件")
	}
	rules := []any{}
	for _, child := range children {
		if len(child) < 2 || child[0] != '(' || child[len(child)-1] != ')' {
			return nil, errors.New("每个子条件需要单独括号")
		}
		parts, err := splitRoutingParts(child[1 : len(child)-1])
		if err != nil {
			return nil, err
		}
		if len(parts) < 2 || len(parts) > 3 {
			return nil, errors.New("子条件不得包含路由动作")
		}
		nr := len(parts) == 3 && parts[2] == "no-resolve"
		if len(parts) == 3 && !nr {
			return nil, errors.New("子条件选项不支持")
		}
		rule, err := singBoxCondition(parts[0], parts[1], nr, depth+1, count, sets...)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	mode := strings.ToLower(kind)
	if kind == "NOT" {
		mode = "and"
	}
	result := Record{"type": "logical", "mode": mode, "rules": rules}
	if kind == "NOT" {
		result["invert"] = true
	}
	return result, nil
}
