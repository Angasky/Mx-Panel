package subscriptions

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

// Strict, independent export: never reuse the basic export's skipped-node list
// for routing, where a missing policy could change the destination of traffic.
func convertSurgeRouting(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	fail := func(message string) (Export, error) { return result, errors.New(message) }
	if source.ClientOptions != nil && (source.ClientOptions.WebRTC || source.ClientOptions.DNSProtection) {
		return fail("Surge 分流导出不能继承 DNS/WebRTC 防护，请使用完整 Mihomo 配置")
	}
	for _, key := range []string{"proxy-providers", "sub-rules"} {
		if v, ok := source.Document[key]; ok && v != nil {
			return fail("Surge 分流暂不支持提供者或子规则：" + key)
		}
	}
	for _, key := range []string{"failovers", "serverChains"} {
		if len(objects(source.Managed[key])) > 0 {
			return fail("Surge 分流暂不支持远端主备或服务器链路")
		}
	}
	for _, key := range []string{"proxies", "proxy-groups"} {
		if source.Document[key] == nil {
			continue
		}
		list, ok := source.Document[key].([]any)
		if !ok {
			return fail("节点和策略组必须为列表")
		}
		for _, item := range list {
			if _, ok := item.(map[string]any); !ok {
				return fail("节点和策略组必须为对象")
			}
		}
	}
	inlineSets, setRefs, setErr := singBoxInlineRuleSets(source.Document["rule-providers"])
	if setErr != nil {
		return fail(setErr.Error())
	}
	expandedSets := map[string]Record{}
	for _, raw := range inlineSets {
		set := raw.(Record)
		rules := set["rules"].([]any)
		// Each provider is an OR, including when used inside NOT or AND.
		condition := Record{"type": "logical", "mode": "or", "rules": rules}
		if len(rules) == 1 {
			condition = rules[0].(Record)
		}
		if _, err := renderSurgeCondition(condition); err != nil {
			return fail(err.Error())
		}
		expandedSets[text(set["tag"])] = condition
	}
	names := map[string]string{"DIRECT": "DIRECT", "REJECT": "REJECT"}
	nodes, groups := objects(source.Document["proxies"]), objects(source.Document["proxy-groups"])
	register := func(name, prefix string, index int) error {
		if name == "" || !utf8.ValidString(name) || names[name] != "" || name == "REJECT-DROP" || name == "PASS" {
			return errors.New("策略名称重复、为空或与内置策略冲突")
		}
		label := strings.TrimPrefix(shadowrocketName(name, strconv.Itoa(index), false), "MX-N-")
		label = strings.ReplaceAll(label, "/", " ")
		names[name] = prefix + label
		return nil
	}
	for i, n := range nodes {
		if e := register(text(n["name"]), "MX-N-", i); e != nil {
			return fail(e.Error())
		}
	}
	for i, g := range groups {
		if e := register(text(g["name"]), "MX-G-", i); e != nil {
			return fail(e.Error())
		}
	}
	graph := map[string][]string{}
	proxies := []string{}
	for _, n := range nodes {
		checked := n
		underlying := ""
		if raw, exists := n["dialer-proxy"]; exists {
			ref, ok := raw.(string)
			if !ok || ref == "" || names[ref] == "" || ref == "DIRECT" || ref == "REJECT" {
				return fail("Surge 中转必须引用已转换的节点或策略组，暂不支持内置策略")
			}
			if n["tfo"] == true {
				return fail("Surge 中转节点暂不支持同时启用 TFO")
			}
			checked = maps.Clone(n)
			delete(checked, "dialer-proxy")
			underlying = names[ref]
			graph[text(n["name"])] = append(graph[text(n["name"])], ref)
		}
		row, e := surgeNode(checked)
		if e != nil {
			return fail("存在不兼容 Surge 的节点：" + e.Error())
		}
		if underlying != "" {
			row += ", underlying-proxy=" + underlying
		}
		proxies = append(proxies, names[text(n["name"])]+" = "+row)
	}
	policyRows := []string{}
	testURL := ""
	for _, g := range groups {
		kind, ok := g["type"].(string)
		if !ok || (kind != "select" && kind != "url-test" && kind != "fallback") {
			return fail("Surge 分流目前支持 select、url-test 和 fallback 策略组")
		}
		for key := range g {
			if key != "name" && key != "type" && key != "proxies" && !((kind == "url-test" || kind == "fallback") && (key == "url" || key == "interval")) && !(kind == "url-test" && key == "tolerance") {
				return fail("策略组含未适配选项：" + key)
			}
		}
		refs, ok := g["proxies"].([]any)
		if !ok || len(refs) == 0 {
			return fail("策略组成员不能为空")
		}
		members := []string{}
		for _, r := range refs {
			name, ok := r.(string)
			if !ok || names[name] == "" || (kind != "select" && name == "REJECT") {
				return fail("策略组引用缺失或不支持的策略")
			}
			members = append(members, names[name])
			graph[text(g["name"])] = append(graph[text(g["name"])], name)
		}
		row := names[text(g["name"])] + " = " + kind + ", " + strings.Join(members, ", ")
		if kind == "url-test" || kind == "fallback" {
			value, ok := g["url"].(string)
			u, e := url.Parse(value)
			if !ok || e != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Hostname() == "" || u.User != nil || u.Fragment != "" || strings.ContainsAny(value, ",;#\"'[]\\") || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
				return fail("测速地址必须为可安全写入配置的 HTTP/HTTPS URL")
			}
			// Current Surge ignores legacy group url=. Use documented global test
			// settings, and refuse conflicting group URLs instead of silently replacing.
			if testURL != "" && testURL != value {
				return fail("当前 Surge 分流导出要求所有测速/故障切换组使用同一测试 URL")
			}
			testURL = value
			interval, e := routingInteger(g["interval"], 300, 1, 86400)
			if e != nil {
				return fail("测速间隔须为 1–86400 秒")
			}
			row += fmt.Sprintf(", interval=%d", interval)
			if kind == "url-test" {
				tolerance, e := routingInteger(g["tolerance"], 50, 0, 65535)
				if e != nil {
					return fail("测速容差须为 0–65535 毫秒")
				}
				row += fmt.Sprintf(", tolerance=%d", tolerance)
			}
		}
		policyRows = append(policyRows, row)
	}
	states := map[string]int{}
	var visit func(string) bool
	visit = func(name string) bool {
		if states[name] == 1 {
			return false
		}
		if states[name] == 2 {
			return true
		}
		states[name] = 1
		for _, child := range graph[name] {
			if !visit(child) {
				return false
			}
		}
		states[name] = 2
		return true
	}
	for name := range graph {
		if !visit(name) {
			return fail("策略组或中转节点存在循环引用")
		}
	}
	sourceRules, ok := source.Document["rules"].([]any)
	if !ok || len(sourceRules) == 0 {
		return fail("Surge 分流需要明确的规则及末尾 MATCH")
	}
	rules := []string{}
	ruleBytes := 0
	final := false
	for i, item := range sourceRules {
		raw, ok := item.(string)
		if !ok || len(raw) > 8192 {
			return fail("规则格式无效或超长")
		}
		parts, splitErr := splitRoutingParts(raw)
		if splitErr != nil {
			return fail("规则括号或长度无效")
		}
		if len(parts) == 2 && parts[0] == "MATCH" {
			if i != len(sourceRules)-1 || names[parts[1]] == "" {
				return fail("MATCH 必须位于末尾并引用有效策略")
			}
			rules = append(rules, "FINAL,"+names[parts[1]])
			final = true
			continue
		}
		if len(parts) != 3 && len(parts) != 4 {
			return fail("规则结构暂不支持")
		}
		kind, value, target := parts[0], parts[1], parts[2]
		if names[target] == "" {
			return fail("规则引用未知策略")
		}
		noResolve := len(parts) == 4 && parts[3] == "no-resolve"
		if len(parts) == 4 && !noResolve {
			return fail("规则选项暂不支持")
		}
		parsed, e := singBoxCondition(kind, value, noResolve, 0, new(int), setRefs)
		if e != nil {
			return fail(e.Error())
		}
		condition, e := renderSurgeCondition(parsed, expandedSets)
		if e != nil {
			return fail(e.Error())
		}
		// Basic IP flags belong after the policy, whereas nested flags remain
		// within each parenthesized condition.
		option := ""
		if strings.HasPrefix(condition, "IP-CIDR,") || strings.HasPrefix(condition, "IP-CIDR6,") {
			condition = strings.TrimSuffix(condition, ",no-resolve")
			option = ",no-resolve"
		}
		line := condition + "," + names[target] + option
		if len(line) > 8192 {
			return fail("规则集展开后的单条 Surge 规则超过 8192 字节")
		}
		ruleBytes += len(line) + 1
		if ruleBytes > 4<<20 {
			return fail("规则集展开后的 Surge 规则超过 4 MiB")
		}
		rules = append(rules, line)
	}
	if !final {
		return fail("缺少末尾 MATCH，拒绝猜测默认出口")
	}
	general := ""
	if testURL != "" {
		general = "[General]\nproxy-test-url = " + testURL + "\ninternet-test-url = " + testURL + "\n\n"
	}
	if len(strings.Join(rules, "\n")) > 4<<20 {
		return fail("规则集展开后的 Surge 规则超过 4 MiB")
	}
	result.Count = len(nodes)
	result.Body = []byte("# MX-Panel Surge routing (experimental); DNS/TUN settings are not converted.\n" + general + "[Proxy]\n" + strings.Join(proxies, "\n") + "\n\n[Proxy Group]\n" + strings.Join(policyRows, "\n") + "\n\n[Rule]\n" + strings.Join(rules, "\n") + "\n")
	return result, nil
}
