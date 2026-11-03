package subscriptions

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

func shadowrocketName(name, scope string, group bool) string {
	sum := sha256.Sum256([]byte(scope + "\x00" + name))
	prefix := "MX-N-"
	if group {
		prefix = "MX-HA-"
	}
	clean := strings.Map(func(r rune) rune {
		if r < 32 || r >= 127 && r <= 159 || r == 0x2028 || r == 0x2029 || strings.ContainsRune(",=;#[]\\\"'", r) {
			return ' '
		}
		return r
	}, name)
	runes := []rune(strings.TrimSpace(clean))
	if len(runes) > 64 {
		runes = runes[:64]
	}
	return prefix + hex.EncodeToString(sum[:])[:16] + " " + string(runes)
}

type rocketGroup struct {
	item     Record
	nodes    []Record
	interval int
}

func rocketGroups(source config.Subscription) ([]rocketGroup, []Record) {
	return managedHAGroups(source, func(node Record) error {
		if node["type"] == "mieru" {
			return errors.New("小火箭不支持 Mieru，请使用完整 Mihomo 订阅")
		}
		_, err := links.Export(node)
		if err != nil {
			return errors.New("路径协议或参数不支持小火箭无损导出")
		}
		return nil
	})
}
func managedHAGroups(source config.Subscription, validate func(Record) error) ([]rocketGroup, []Record) {
	result := []rocketGroup{}
	skipped := []Record{}
	index := func(values any, key string) (map[string]Record, bool) {
		out := map[string]Record{}
		for _, row := range objects(values) {
			name := text(row[key])
			if name == "" || out[name] != nil {
				return nil, false
			}
			out[name] = row
		}
		return out, true
	}
	nodes, nOK := index(source.Document["proxies"], "name")
	groups, gOK := index(source.Document["proxy-groups"], "name")
	chains, cOK := index(source.Managed["serverChains"], "name")
	active := map[string]bool{}
	for _, b := range objects(source.Managed["remoteNodes"]) {
		id, e := strconv.Atoi(text(b["inboundId"]))
		if b["status"] == "active" && text(b["serverId"]) != "" && e == nil && id > 0 {
			active[text(b["serverId"])+"/"+text(b["inboundId"])] = true
		}
	}
	seenGroups := map[string]bool{}
	for _, item := range objects(source.Managed["failovers"]) {
		name := text(item["name"])
		reason := ""
		interval, e := number(item["interval"], 0)
		paths, ok := item["paths"].([]any)
		if name == "" || seenGroups[name] {
			reason = "主备组名称为空或重复"
		} else if text(item["exit"]) == "" {
			reason = "固定出口无效"
		} else if !nOK || !gOK || !cOK {
			reason = "主备组件名称重复或无效"
		} else if e != nil || interval < 10 || interval > 600 {
			reason = "主备检测间隔无效"
		} else if item["status"] != "active" || !ok || len(paths) < 2 || len(paths) > 8 {
			reason = "主备组尚未完成创建或正在清理"
		}
		seenGroups[name] = true
		selected := []Record{}
		seen := map[string]bool{}
		group := groups[name]
		members, _ := group["proxies"].([]any)
		if reason == "" && (group["type"] != "fallback" || len(members) != len(paths)) {
			reason = "主备组与受管路径不一致"
		}
		for i, path := range paths {
			if reason != "" {
				break
			}
			pathName, ok := path.(string)
			chain := chains[pathName]
			node := nodes[pathName]
			if !ok || pathName == "" || seen[pathName] || members[i] != path {
				reason = "主备路径顺序或名称无效"
				break
			}
			seen[pathName] = true
			if chain == nil || !active[text(chain["serverId"])+"/"+text(chain["inboundId"])] || text(chain["exit"]) != text(item["exit"]) {
				reason = "路径缺少有效订阅绑定或出口不一致"
				break
			}
			if node == nil || text(node["dialer-proxy"]) != "" || !utf8.ValidString(pathName) {
				reason = "路径节点缺失或不是独立服务器转发"
				break
			}
			if err := validate(node); err != nil {
				reason = err.Error()
				break
			}
			selected = append(selected, node)
		}
		if reason != "" {
			skipped = append(skipped, Record{"name": name, "type": "fallback", "reason": reason})
			continue
		}
		result = append(result, rocketGroup{item, selected, int(interval)})
	}
	return result, skipped
}

func convertRocketHA(source config.Subscription, configuration bool) (Export, error) {
	groups, skipped := rocketGroups(source)
	result := Export{Skipped: skipped}
	if len(groups) == 0 {
		return result, errors.New("请先创建有效的多入口服务器主备组")
	}
	if configuration {
		lines := []string{"# Mxioc Shadowrocket: import the paired node subscription first.", "# Do not enable global fallback.", "[General]", "udp-policy-not-supported-behaviour = REJECT", "", "[Proxy Group]"}
		labels := []string{}
		for _, g := range groups {
			labels = append(labels, shadowrocketName(text(g.item["name"]), source.Slug, true))
		}
		lines = append(lines, "MX-Select = select,"+strings.Join(labels, ","))
		for i, g := range groups {
			aliases := []string{}
			for _, node := range g.nodes {
				aliases = append(aliases, shadowrocketName(text(node["name"]), source.Slug, false))
			}
			lines = append(lines, labels[i]+" = fallback,"+strings.Join(aliases, ",")+",interval="+strconv.Itoa(g.interval)+",timeout=5,url=https://www.gstatic.com/generate_204")
		}
		lines = append(lines, "", "[Rule]", "FINAL,MX-Select", "")
		result.Body = []byte(strings.Join(lines, "\n"))
		result.Count = len(groups)
		return result, nil
	}
	uris := []string{}
	seen := map[string]bool{}
	for _, g := range groups {
		for _, node := range g.nodes {
			name := text(node["name"])
			if seen[name] {
				continue
			}
			seen[name] = true
			copy := Record{}
			for k, v := range node {
				copy[k] = v
			}
			copy["name"] = shadowrocketName(name, source.Slug, false)
			uri, err := links.Export(copy)
			if err != nil {
				return result, fmt.Errorf("主备节点导出失败")
			}
			uris = append(uris, uri)
		}
	}
	result.Count = len(uris)
	result.Body = []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(uris, "\n"))))
	return result, nil
}
