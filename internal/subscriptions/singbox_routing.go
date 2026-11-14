package subscriptions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

// This separate export is strict: no partial routing or silently removed nodes.
func convertSingBoxRouting(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	fail := func(message string) (Export, error) { return result, errors.New(message) }
	if source.ClientOptions != nil && (source.ClientOptions.WebRTC || source.ClientOptions.DNSProtection) {
		return fail("分流导出不能等价转换 DNS/WebRTC 防护，请使用完整 Mihomo 配置")
	}
	for _, key := range []string{"proxy-providers", "rule-providers", "sub-rules"} {
		if v, ok := source.Document[key]; ok && v != nil {
			return fail("分流导出暂不支持提供者或子规则：" + key)
		}
	}
	for _, key := range []string{"failovers", "serverChains"} {
		if len(objects(source.Managed[key])) > 0 {
			return fail("分流导出暂不支持远端主备或中转链路")
		}
	}
	for _, key := range []string{"proxies", "proxy-groups"} {
		if source.Document[key] == nil {
			continue
		}
		values, ok := source.Document[key].([]any)
		if !ok {
			return fail("节点或策略组必须为列表")
		}
		for _, v := range values {
			if _, ok := v.(map[string]any); !ok {
				return fail("节点或策略组必须为对象")
			}
		}
	}
	names := map[string]string{"DIRECT": "mx-direct"}
	nodes := objects(source.Document["proxies"])
	groups := objects(source.Document["proxy-groups"])
	register := func(name, tag string) error {
		if name == "" || name == "REJECT" || name == "REJECT-DROP" || name == "PASS" || names[name] != "" {
			return errors.New("节点或策略组名称重复、为空或与内置策略冲突")
		}
		names[name] = tag
		return nil
	}
	for i, n := range nodes {
		if err := register(text(n["name"]), fmt.Sprintf("mx-node-%d %s", i+1, text(n["name"]))); err != nil {
			return fail(err.Error())
		}
	}
	for i, g := range groups {
		if err := register(text(g["name"]), fmt.Sprintf("mx-group-%d %s", i+1, text(g["name"]))); err != nil {
			return fail(err.Error())
		}
	}
	outbounds := []any{Record{"type": "direct", "tag": "mx-direct"}}
	for _, n := range nodes {
		if n["dialer-proxy"] != nil {
			return fail("分流导出不支持链式节点")
		}
		outbound, err := remote.SingBoxOutbound(n, names[text(n["name"])])
		if err != nil {
			return fail("存在不兼容 sing-box 的节点，请先查看基础导出的兼容报告")
		}
		outbounds = append(outbounds, outbound)
	}
	graph := map[string][]string{}
	for _, g := range groups {
		if g["type"] != "select" {
			return fail("分流导出当前仅支持 select 手动策略组")
		}
		for key := range g {
			if key != "name" && key != "type" && key != "proxies" {
				return fail("策略组含尚未适配的选项：" + key)
			}
		}
		refs, ok := g["proxies"].([]any)
		if !ok || len(refs) == 0 {
			return fail("策略组不能为空")
		}
		members := []string{}
		for _, ref := range refs {
			name, ok := ref.(string)
			if !ok || names[name] == "" {
				return fail("策略组引用缺失或不支持的策略（含拒绝策略）")
			}
			members = append(members, names[name])
			graph[text(g["name"])] = append(graph[text(g["name"])], name)
		}
		outbounds = append(outbounds, Record{"type": "selector", "tag": names[text(g["name"])], "outbounds": members, "default": members[0]})
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
		for _, child := range graph[name] {
			if !visit(child) {
				return false
			}
		}
		state[name] = 2
		return true
	}
	for name := range graph {
		if !visit(name) {
			return fail("策略组存在循环引用")
		}
	}
	rules := []any{}
	sourceRules, ok := source.Document["rules"].([]any)
	if !ok || len(sourceRules) == 0 {
		return fail("分流导出需要明确的规则及末尾 MATCH 策略")
	}
	final := ""
	for i, item := range sourceRules {
		raw, ok := item.(string)
		if !ok {
			return fail("规则格式无效")
		}
		parts := strings.Split(raw, ",")
		if len(parts) < 2 || len(parts) > 4 {
			return fail(fmt.Sprintf("第 %d 条规则结构不支持", i+1))
		}
		kind := parts[0]
		actionIndex := len(parts) - 1
		noResolve := false
		if parts[actionIndex] == "no-resolve" {
			noResolve = true
			actionIndex--
		}
		target := parts[actionIndex]
		if kind == "MATCH" {
			if len(parts) != 2 || i != len(sourceRules)-1 || names[target] == "" {
				return fail("MATCH 必须位于末尾并指向可转换策略")
			}
			final = names[target]
			continue
		}
		if actionIndex != 2 {
			return fail("规则参数数量不支持")
		}
		rule := Record{}
		switch kind {
		case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
			if noResolve || strings.TrimSpace(parts[1]) != parts[1] || parts[1] == "" || strings.ContainsAny(parts[1], "\r\n\t /\\") {
				return fail("域名规则值或选项无效")
			}
			key := map[string]string{"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword"}[kind]
			rule[key] = []string{parts[1]}
		case "IP-CIDR", "IP-CIDR6":
			// DNS resolution semantics differ; only explicit no-resolve is lossless.
			prefix, err := netip.ParsePrefix(parts[1])
			if err != nil || !noResolve || prefix.Addr().Is4In6() || (kind == "IP-CIDR") != prefix.Addr().Is4() {
				return fail("IP 规则必须为对应地址族 CIDR 且显式 no-resolve")
			}
			rule["ip_cidr"] = []string{prefix.Masked().String()}
		case "DST-PORT":
			port, err := strconv.Atoi(parts[1])
			if err != nil || port < 1 || port > 65535 || noResolve {
				return fail("目标端口规则无效")
			}
			rule["port"] = []int{port}
		case "NETWORK":
			if (parts[1] != "tcp" && parts[1] != "udp") || noResolve {
				return fail("网络规则只支持 tcp/udp")
			}
			rule["network"] = []string{parts[1]}
		default:
			return fail(fmt.Sprintf("第 %d 条规则类型 %s 暂未适配", i+1, kind))
		}
		if target == "REJECT" {
			rule["action"] = "reject"
		} else if names[target] != "" {
			rule["action"] = "route"
			rule["outbound"] = names[target]
		} else {
			return fail("规则引用未知或不支持的策略")
		}
		rules = append(rules, rule)
	}
	if final == "" {
		return fail("缺少末尾 MATCH 策略，拒绝猜测默认出口")
	}
	doc := Record{"log": Record{"level": "warn"}, "inbounds": []any{Record{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}}, "outbounds": outbounds, "route": Record{"rules": rules, "final": final}}
	result.Count = len(nodes)
	var err error
	result.Body, err = json.MarshalIndent(doc, "", "  ")
	return result, err
}
