package subscriptions

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode"

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
	for _, key := range []string{"proxy-providers", "sub-rules"} {
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
	ruleSets, setRefs, setErr := singBoxInlineRuleSets(source.Document["rule-providers"])
	if setErr != nil {
		return fail(setErr.Error())
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
		if g["type"] != "select" && g["type"] != "url-test" {
			return fail("分流导出当前支持 select 和 url-test 策略组，暂不支持故障切换、负载均衡及链路组")
		}
		for key := range g {
			if key != "name" && key != "type" && key != "proxies" && !(g["type"] == "url-test" && (key == "url" || key == "interval" || key == "tolerance")) {
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
		group := Record{"type": "selector", "tag": names[text(g["name"])], "outbounds": members, "default": members[0]}
		if g["type"] == "url-test" {
			testURL, ok := g["url"].(string)
			u, err := url.Parse(testURL)
			if !ok || err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.TrimSpace(testURL) != testURL {
				return fail("自动测速组需要有效的 HTTP/HTTPS 测试地址，不能包含登录凭据或片段")
			}
			interval, err := routingInteger(g["interval"], 300, 1, 86400)
			if err != nil {
				return fail("测速间隔须为 1–86400 秒的整数")
			}
			tolerance, err := routingInteger(g["tolerance"], 50, 0, 65535)
			if err != nil {
				return fail("测速容差须为 0–65535 毫秒的整数")
			}
			group = Record{"type": "urltest", "tag": names[text(g["name"])], "outbounds": members, "url": testURL, "interval": fmt.Sprintf("%ds", interval), "tolerance": tolerance}
		}
		outbounds = append(outbounds, group)
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
		parts, splitErr := splitRoutingParts(raw)
		if splitErr != nil {
			return fail(fmt.Sprintf("第 %d 条规则括号或长度无效", i+1))
		}
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
		rule, err := singBoxCondition(kind, parts[1], noResolve, 0, new(int), setRefs)
		if err != nil {
			return fail(fmt.Sprintf("第 %d 条规则：%s", i+1, err.Error()))
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
	doc := Record{"log": Record{"level": "warn"}, "inbounds": []any{Record{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}}, "outbounds": outbounds, "route": Record{"rules": rules, "final": final, "rule_set": ruleSets}}
	if routingUsesProcess(rules) || routingUsesProcess(ruleSets) {
		doc["route"].(Record)["find_process"] = true
	}
	result.Count = len(nodes)
	var err error
	result.Body, err = json.MarshalIndent(doc, "", "  ")
	return result, err
}

// Configuration numbers may be YAML integers or JSON numbers; reject fractions
// rather than silently changing the test interval or tolerance.
func routingInteger(value any, fallback, min, max int) (int, error) {
	if value == nil {
		return fallback, nil
	}
	var raw string
	switch n := value.(type) {
	case int:
		raw = strconv.Itoa(n)
	case int64:
		raw = strconv.FormatInt(n, 10)
	case uint64:
		raw = strconv.FormatUint(n, 10)
	case json.Number:
		raw = n.String()
	default:
		return 0, errors.New("需要整数")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < min || n > max {
		return 0, errors.New("整数超出范围")
	}
	return n, nil
}

func singBoxBasicCondition(kind, value string, noResolve bool) (Record, error) {
	parts := []string{kind, value}
	rule := Record{}
	switch kind {
	case "DOMAIN", "DOMAIN-SUFFIX", "DOMAIN-KEYWORD":
		if noResolve || strings.TrimSpace(parts[1]) != parts[1] || parts[1] == "" || strings.ContainsAny(parts[1], "\r\n\t /\\") {
			return nil, errors.New("域名规则值或选项无效")
		}
		key := map[string]string{"DOMAIN": "domain", "DOMAIN-SUFFIX": "domain_suffix", "DOMAIN-KEYWORD": "domain_keyword"}[kind]
		rule[key] = []string{parts[1]}
	case "IP-CIDR", "IP-CIDR6":
		// DNS resolution semantics differ; only explicit no-resolve is lossless.
		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil || !noResolve || prefix.Addr().Is4In6() || (kind == "IP-CIDR") != prefix.Addr().Is4() {
			return nil, errors.New("IP 规则必须为对应地址族 CIDR 且显式 no-resolve")
		}
		rule["ip_cidr"] = []string{prefix.Masked().String()}
	case "SRC-IP-CIDR":
		prefix, err := netip.ParsePrefix(parts[1])
		if err != nil || prefix.Addr().Is4In6() || noResolve {
			return nil, errors.New("源 IP 规则必须为有效 CIDR，不支持额外选项")
		}
		rule["source_ip_cidr"] = []string{prefix.Masked().String()}
	case "DST-PORT", "SRC-PORT":
		if noResolve {
			return nil, errors.New("端口规则不支持 no-resolve")
		}
		key := "port"
		if kind == "SRC-PORT" {
			key = "source_port"
		}
		condition, err := singBoxPortCondition(key, parts[1])
		if err != nil {
			return nil, err
		}
		return condition, nil
	case "PROCESS-PATH":
		value := parts[1]
		absolute := strings.HasPrefix(value, "/") || len(value) > 2 && ((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) && value[1] == ':' && (value[2] == '\\' || value[2] == '/')
		if noResolve || len(value) > 2048 || !absolute || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, errors.New("进程路径需为有效桌面系统绝对路径，不支持额外选项")
		}
		// Mihomo exact path matching is case insensitive; sing-box's literal
		// process_path is case sensitive, so preserve semantics with quoted regex.
		rule["process_path_regex"] = []string{"(?i)^" + regexp.QuoteMeta(value) + "$"}
	case "NETWORK":
		network := strings.ToLower(parts[1])
		if (network != "tcp" && network != "udp") || noResolve {
			return nil, errors.New("网络规则只支持 TCP/UDP")
		}
		rule["network"] = []string{network}
	default:
		return nil, errors.New("规则类型暂未适配：" + kind)
	}
	return rule, nil
}

func routingUsesProcess(values []any) bool {
	for _, v := range values {
		r, ok := v.(Record)
		if !ok {
			continue
		}
		if r["process_path_regex"] != nil {
			return true
		}
		if children, ok := r["rules"].([]any); ok && routingUsesProcess(children) {
			return true
		}
	}
	return false
}
func singBoxPortCondition(key, value string) (Record, error) {
	parts := strings.Split(value, "/")
	if len(parts) > 28 {
		return nil, errors.New("端口规则最多 28 段")
	}
	ports := []int{}
	ranges := []string{}
	for _, part := range parts {
		bounds := strings.Split(part, "-")
		if len(bounds) > 2 {
			return nil, errors.New("端口范围格式无效")
		}
		start, err := routingPort(bounds[0])
		if err != nil {
			return nil, err
		}
		if len(bounds) == 1 {
			ports = append(ports, start)
			continue
		}
		end, err := routingPort(bounds[1])
		if err != nil || end < start {
			return nil, errors.New("端口范围必须递增且介于 1–65535")
		}
		ranges = append(ranges, fmt.Sprintf("%d:%d", start, end))
	}
	// sing-box combines these two fields with OR within the same port group.
	result := Record{}
	if len(ports) > 0 {
		result[key] = ports
	}
	if len(ranges) > 0 {
		result[key+"_range"] = ranges
	}
	return result, nil
}
func routingPort(raw string) (int, error) {
	if raw == "" {
		return 0, errors.New("端口不能为空")
	}
	for _, ch := range raw {
		if ch < '0' || ch > '9' {
			return 0, errors.New("端口必须为数字")
		}
	}
	port, err := strconv.Atoi(raw)
	if err != nil || port < 1 || port > 65535 {
		return 0, errors.New("端口须介于 1–65535")
	}
	return port, nil
}
