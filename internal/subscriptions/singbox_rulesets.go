package subscriptions

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
)

type routingRuleSet struct {
	Tag               string
	RequiresNoResolve bool
}

func singBoxInlineRuleSets(value any) ([]any, map[string]routingRuleSet, error) {
	result := []any{}
	refs := map[string]routingRuleSet{}
	if value == nil {
		return result, refs, nil
	}
	providers, ok := value.(map[string]any)
	if !ok || len(providers) > 64 {
		return nil, nil, errors.New("内嵌规则集必须为对象，最多 64 个")
	}
	keys := []string{}
	for key := range providers {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	total := 0
	for i, name := range keys {
		p, ok := providers[name].(map[string]any)
		if !ok || p["type"] != "inline" {
			return nil, nil, errors.New("规则集目前只支持 type: inline，不读取远程或本地文件")
		}
		if strings.TrimSpace(name) == "" {
			return nil, nil, errors.New("规则集名称不能为空")
		}
		for key := range p {
			if key != "type" && key != "behavior" && key != "payload" {
				return nil, nil, errors.New("内嵌规则集含未适配参数：" + key)
			}
		}
		payload, ok := p["payload"].([]any)
		if !ok || len(payload) == 0 {
			return nil, nil, errors.New("内嵌规则集 payload 必须为非空列表")
		}
		total += len(payload)
		if total > 4096 {
			return nil, nil, errors.New("内嵌规则集总计最多 4096 条")
		}
		tag := fmt.Sprintf("mx-rules-%d", i+1)
		requiresIP := false
		rules := []any{}
		for _, item := range payload {
			raw, ok := item.(string)
			if !ok || len(raw) > 8192 {
				return nil, nil, errors.New("规则集条目必须为限长文本")
			}
			var rule Record
			var err error
			switch p["behavior"] {
			case "domain":
				kind, value := "DOMAIN", raw
				if strings.HasPrefix(value, "+.") {
					kind = "DOMAIN-SUFFIX"
					value = strings.TrimPrefix(value, "+.")
				}
				if strings.ContainsAny(value, "*+,()") || strings.HasPrefix(value, ".") {
					return nil, nil, errors.New("domain 规则集仅支持精确域名及 +.后缀，不支持其他通配语法")
				}
				rule, err = singBoxBasicCondition(kind, value, false)
			case "ipcidr":
				prefix, e := netip.ParsePrefix(raw)
				if e != nil || prefix.Addr().Is4In6() {
					return nil, nil, errors.New("ipcidr 规则集条目必须为有效 CIDR")
				}
				rule = Record{"ip_cidr": []string{prefix.Masked().String()}}
				requiresIP = true
			case "classical":
				parts, e := splitRoutingParts(raw)
				if e != nil || len(parts) < 2 || len(parts) > 3 {
					return nil, nil, errors.New("classical 条目结构无效")
				}
				nr := len(parts) == 3 && parts[2] == "no-resolve"
				if len(parts) == 3 && !nr {
					return nil, nil, errors.New("规则集条目不能携带路由动作")
				}
				rule, err = singBoxCondition(parts[0], parts[1], nr, 0, new(int))
				if routingConditionHasIP(rule) {
					requiresIP = true
				}
			default:
				return nil, nil, errors.New("内嵌规则集仅支持 domain、ipcidr、classical")
			}
			if err != nil {
				return nil, nil, err
			}
			rules = append(rules, rule)
		}
		refs[name] = routingRuleSet{Tag: tag, RequiresNoResolve: requiresIP}
		result = append(result, Record{"type": "inline", "tag": tag, "rules": rules})
	}
	return result, refs, nil
}
func routingConditionHasIP(rule Record) bool {
	if rule["ip_cidr"] != nil {
		return true
	}
	children, _ := rule["rules"].([]any)
	for _, child := range children {
		if r, ok := child.(Record); ok && routingConditionHasIP(r) {
			return true
		}
	}
	return false
}
