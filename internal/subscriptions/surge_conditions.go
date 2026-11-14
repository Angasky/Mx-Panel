package subscriptions

import (
	"errors"
	"fmt"
	"strings"
)

// Share the bounded Mihomo grammar, but emit only conditions with an explicit
// Surge mapping. Unsupported fields must not disappear during rendering.
func surgeRoutingCondition(kind, value string, noResolve bool) (string, error) {
	r, e := singBoxCondition(kind, value, noResolve, 0, new(int))
	if e != nil {
		return "", e
	}
	return renderSurgeCondition(r)
}
func renderSurgeCondition(r Record) (string, error) {
	fail := func() (string, error) { return "", errors.New("Surge 分流规则类型或条件暂未适配") }
	if r["type"] == "logical" {
		for k := range r {
			if k != "type" && k != "mode" && k != "rules" && k != "invert" {
				return fail()
			}
		}
		children, ok := r["rules"].([]any)
		if !ok || len(children) == 0 {
			return fail()
		}
		parts := []string{}
		for _, child := range children {
			c, ok := child.(Record)
			if !ok {
				return fail()
			}
			text, e := renderSurgeCondition(c)
			if e != nil {
				return "", e
			}
			parts = append(parts, "("+text+")")
		}
		mode := strings.ToUpper(text(r["mode"]))
		if mode != "AND" && mode != "OR" {
			return fail()
		}
		if r["invert"] == true {
			if len(parts) != 1 || mode != "AND" {
				return fail()
			}
			mode = "NOT"
		}
		return mode + ",(" + strings.Join(parts, ",") + ")", nil
	}
	if len(r) == 1 {
		for key, kind := range map[string]string{"domain": "DOMAIN", "domain_suffix": "DOMAIN-SUFFIX", "domain_keyword": "DOMAIN-KEYWORD", "ip_cidr": "IP-CIDR", "source_ip_cidr": "SRC-IP", "network": "PROTOCOL"} {
			raw, exists := r[key]
			if !exists {
				continue
			}
			values, ok := raw.([]string)
			if !ok || len(values) != 1 {
				return fail()
			}
			v := values[0]
			switch key {
			case "domain", "domain_suffix", "domain_keyword":
				if !surgeAtom(v) || strings.ContainsAny(v, "/=()*?+") {
					return "", errors.New("域名规则值无效")
				}
				v = strings.ToLower(v)
			case "ip_cidr":
				if strings.Contains(v, ":") {
					kind = "IP-CIDR6"
				}
				return kind + "," + v + ",no-resolve", nil
			case "network":
				if v != "tcp" && v != "udp" {
					return fail()
				}
				v = strings.ToUpper(v)
			}
			return kind + "," + v, nil
		}
	}
	for key, kind := range map[string]string{"port": "DEST-PORT", "source_port": "SRC-PORT"} {
		if r[key] == nil && r[key+"_range"] == nil {
			continue
		}
		for field := range r {
			if field != key && field != key+"_range" {
				return fail()
			}
		}
		parts := []string{}
		if raw := r[key]; raw != nil {
			ports, ok := raw.([]int)
			if !ok {
				return fail()
			}
			for _, p := range ports {
				parts = append(parts, fmt.Sprintf("%s,%d", kind, p))
			}
		}
		if raw := r[key+"_range"]; raw != nil {
			ranges, ok := raw.([]string)
			if !ok {
				return fail()
			}
			for _, p := range ranges {
				parts = append(parts, kind+","+strings.ReplaceAll(p, ":", "-"))
			}
		}
		if len(parts) == 1 {
			return parts[0], nil
		}
		if len(parts) == 0 {
			return fail()
		}
		for i := range parts {
			parts[i] = "(" + parts[i] + ")"
		}
		return "OR,(" + strings.Join(parts, ",") + ")", nil
	}
	return fail()
}
