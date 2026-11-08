package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// EditNode avoids cloning the complete configuration for an identical PUT.
// It still validates the submitted node and verifies every mirror before
// skipping the transaction; a damaged mirror goes through normal repair.
func (r *Repository) EditNode(id, method string, payload Document) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if method == "PUT" {
		p, err := r.profile(id)
		if err != nil {
			return err
		}
		doc, raw, err := r.cachedRead(p)
		if err != nil {
			return err
		}
		if submitted, ok := payload["config"].(map[string]any); ok {
			next := cloneConfig(submitted).(Document)
			if err := ValidateNode(next); err != nil {
				return err
			}
			for _, item := range rows(doc, "proxies") {
				old := item.(Document)
				if old["name"] != payload["oldName"] || !equalConfig(old, next) {
					continue
				}
				healthy := true
				for _, path := range p.Files {
					mirror, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(raw, mirror) {
						healthy = false
						break
					}
				}
				if healthy {
					return nil
				}
				break
			}
		}
	}
	return r.mutateLocked(id, func(doc Document) error { return EditNode(doc, method, payload) })
}

var uuid = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
var domain = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)
var supported = map[string]bool{"vless": true, "vmess": true, "ss": true, "trojan": true, "hysteria2": true, "tuic": true, "snell": true, "mieru": true, "socks5": true, "http": true}

func stringValue(v any) string { s, _ := v.(string); return s }
func integer(v any) (int, error) {
	switch n := v.(type) {
	case int:
		return n, nil
	case json.Number:
		i, err := strconv.ParseInt(string(n), 10, 32)
		return int(i), err
	case int64:
		return int(n), nil
	}
	return 0, errors.New("必须填写整数")
}
func ValidateNode(node map[string]any) error {
	if node == nil {
		return errors.New("节点配置必须为对象")
	}
	if err := normalizeNumbers(node); err != nil {
		return err
	}
	name := stringValue(node["name"])
	kind := stringValue(node["type"])
	host := stringValue(node["server"])
	if strings.TrimSpace(name) == "" || len(name) > 1024 || strings.ContainsAny(name, "\r\n\x00") {
		return errors.New("节点名称无效")
	}
	if !supported[kind] {
		return errors.New("暂不支持该节点协议")
	}
	if host == "" || len(host) > 253 || net.ParseIP(host) == nil && !domain.MatchString(host) {
		return errors.New("服务器地址无效")
	}
	if kind == "mieru" {
		normalized, err := links.NormalizeMieru(node)
		if err != nil {
			return err
		}
		for key := range node {
			delete(node, key)
		}
		for key, v := range normalized {
			node[key] = v
		}
	}
	if kind != "mieru" || node["port-range"] == nil {
		port, err := integer(node["port"])
		if err != nil || port < 1 || port > 65535 {
			return errors.New("节点端口必须在 1–65535 之间")
		}
	}
	if kind == "vless" || kind == "vmess" || kind == "tuic" {
		if !uuid.MatchString(stringValue(node["uuid"])) {
			return errors.New("节点 UUID 无效")
		}
	}
	if kind == "ss" || kind == "trojan" || kind == "hysteria2" || kind == "tuic" || kind == "mieru" {
		if stringValue(node["password"]) == "" {
			return errors.New("节点密码不能为空")
		}
	}
	if kind == "hysteria2" || kind == "tuic" {
		if raw, exists := node["alpn"]; exists {
			list, err := links.ALPNValues(raw, true)
			if err != nil {
				return errors.New("QUIC ALPN 必须为有效协议字符串或字符串数组")
			}
			node["alpn"] = list
		}
	}
	if kind == "ss" {
		cipher := stringValue(node["cipher"])
		if cipher == "" {
			return errors.New("Shadowsocks 加密方式不能为空")
		}
		if strings.HasPrefix(cipher, "2022-") {
			if err := links.ValidateSS2022Password(cipher, stringValue(node["password"])); err != nil {
				return errors.New("Shadowsocks 2022 \u5bc6\u94a5\u6216\u52a0\u5bc6\u65b9\u5f0f\u65e0\u6548")
			}
		}
	}
	if kind == "snell" {
		normalized, err := links.NormalizeSnell(node)
		if err != nil {
			return err
		}
		for key := range node {
			delete(node, key)
		}
		for key, v := range normalized {
			node[key] = v
		}
	}
	if raw, exists := node["reality-opts"]; exists {
		if kind != "vless" || node["tls"] != true {
			return errors.New("Reality 要求 VLESS 和 TLS")
		}
		opts, err := links.NormalizeReality(raw)
		if err != nil {
			return errors.New("Reality 公钥、short ID 或混合握手参数无效")
		}
		node["reality-opts"] = opts
	}
	if node["dialer-proxy"] == name {
		return errors.New("节点不能以前置中转引用自身")
	}
	if flow := stringValue(node["flow"]); flow != "" {
		network := stringValue(node["network"])
		if (flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443") || kind != "vless" || node["tls"] != true || network != "" && network != "tcp" {
			return errors.New("Vision 要求 VLESS、TLS 和 TCP 传输")
		}
	}
	return nil
}

// json.Decoder.UseNumber protects traffic-sized integers, but json.Number's
// underlying string must not be emitted as a quoted YAML port or version.
func normalizeNumbers(value any) error {
	convert := func(v any) (any, error) {
		n, ok := v.(json.Number)
		if !ok {
			return v, nil
		}
		if !strings.ContainsAny(string(n), ".eE") {
			i, err := n.Int64()
			if err != nil {
				return nil, errors.New("整数超出支持范围")
			}
			return i, nil
		}
		f, err := n.Float64()
		if err != nil {
			return nil, errors.New("数值超出支持范围")
		}
		return f, nil
	}
	switch v := value.(type) {
	case map[string]any:
		for key, item := range v {
			next, err := convert(item)
			if err != nil {
				return err
			}
			v[key] = next
			if err = normalizeNumbers(next); err != nil {
				return err
			}
		}
	case []any:
		for i, item := range v {
			next, err := convert(item)
			if err != nil {
				return err
			}
			v[i] = next
			if err = normalizeNumbers(next); err != nil {
				return err
			}
		}
	}
	return nil
}

// EditNode retains unknown protocol fields and updates named references on rename.
func EditNode(doc Document, method string, payload map[string]any) error {
	nodes := rows(doc, "proxies")
	old := stringValue(payload["oldName"])
	if method == "DELETE" {
		old = stringValue(payload["name"])
	}
	index := -1
	for i, v := range nodes {
		if v.(map[string]any)["name"] == old {
			index = i
			break
		}
	}
	if method != "POST" && index < 0 {
		return errors.New("原节点不存在")
	}
	if method == "DELETE" {
		for _, v := range nodes {
			if v.(map[string]any)["dialer-proxy"] == old {
				return errors.New("节点仍被链式代理引用，请先移除链路")
			}
		}
		nodes = append(nodes[:index], nodes[index+1:]...)
		doc["proxies"] = nodes
		replaceReferences(doc, old, "")
		return nil
	}
	node, ok := payload["config"].(map[string]any)
	if !ok {
		return errors.New("节点配置必须为对象")
	}
	if err := ValidateNode(node); err != nil {
		return err
	}
	name := stringValue(node["name"])
	for i, v := range nodes {
		if i != index && v.(map[string]any)["name"] == name {
			return errors.New("节点名称已存在")
		}
	}
	for _, v := range rows(doc, "proxy-groups") {
		if v.(map[string]any)["name"] == name {
			return errors.New("节点名称与策略组重复")
		}
	}
	if method == "POST" {
		doc["proxies"] = append(nodes, node)
		if payload["addToGroups"] == true {
			for _, v := range rows(doc, "proxy-groups") {
				group := v.(map[string]any)
				if group["type"] != "select" || excludedNodeGroups[stringValue(group["name"])] {
					continue
				}
				refs, _ := group["proxies"].([]any)
				group["proxies"] = append(refs, name)
			}
		}
	} else {
		nodes[index] = node
		doc["proxies"] = nodes
		if old != name {
			replaceReferences(doc, old, name)
		}
	}
	return nil
}
func replaceReferences(doc Document, old, name string) {
	for _, v := range rows(doc, "proxy-groups") {
		group := v.(map[string]any)
		refs, _ := group["proxies"].([]any)
		updated := []any{}
		for _, ref := range refs {
			if ref == old {
				if name != "" {
					updated = append(updated, name)
				}
			} else {
				updated = append(updated, ref)
			}
		}
		group["proxies"] = updated
	}
	if name != "" {
		for _, v := range rows(doc, "proxies") {
			node := v.(map[string]any)
			if node["dialer-proxy"] == old {
				node["dialer-proxy"] = name
			}
		}
	}
	updated := []any{}
	for _, value := range rows(doc, "rules") {
		raw := value.(string)
		parts := RuleParts(raw)
		if parts["action"] == old {
			if name == "" {
				continue
			}
			end := len(raw)
			if options := stringValue(parts["options"]); options != "" {
				end -= len(options) + 1
			}
			raw = raw[:end-len(old)] + name + raw[end:]
		}
		updated = append(updated, raw)
	}
	doc["rules"] = updated
}

func (r *Repository) MoveNode(id string, payload map[string]any) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	profile, err := r.profile(id)
	if err != nil {
		return err
	}
	excluded := map[string]bool{}
	for _, group := range profile.Failovers {
		excluded[stringValue(group["name"])] = true
	}
	return r.mutateLocked(id, func(doc Document) error { return moveNode(doc, payload, excluded) })
}

func MoveNode(doc Document, payload map[string]any) error {
	return moveNode(doc, payload, nil)
}

func moveNode(doc Document, payload map[string]any, excluded map[string]bool) error {
	nodes := rows(doc, "proxies")
	name := stringValue(payload["name"])
	from := -1
	for i, v := range nodes {
		if v.(map[string]any)["name"] == name {
			from = i
			break
		}
	}
	if from < 0 {
		return errors.New("节点不存在")
	}
	targetName := stringValue(payload["targetName"])
	to := -1
	if targetName != "" {
		if targetName == name {
			return nil
		}
		for i, v := range nodes {
			if v.(map[string]any)["name"] == targetName {
				to = i
				break
			}
		}
		if to < 0 {
			return errors.New("目标节点不存在")
		}
		position := "before"
		if _, exists := payload["position"]; exists {
			position = stringValue(payload["position"])
		}
		if position != "before" && position != "after" {
			return errors.New("排序位置无效")
		}
		if from < to {
			to--
		}
		if position == "after" {
			to++
		}
	} else {
		direction, err := integer(payload["direction"])
		if err != nil || direction != 1 && direction != -1 {
			return errors.New("移动方向无效")
		}
		to = from + direction
		if to < 0 || to >= len(nodes) {
			return nil
		}
	}
	node := nodes[from]
	nodes = append(nodes[:from], nodes[from+1:]...)
	nodes = append(nodes, nil)
	copy(nodes[to+1:], nodes[to:])
	nodes[to] = node
	doc["proxies"] = nodes
	order := map[string]int{}
	for i, v := range nodes {
		order[stringValue(v.(map[string]any)["name"])] = i
	}
	for _, v := range rows(doc, "proxy-groups") {
		group := v.(map[string]any)
		if excluded[stringValue(group["name"])] {
			continue
		}
		refs, ok := group["proxies"].([]any)
		if !ok {
			continue
		}
		slots := []int{}
		members := []string{}
		for i, v := range refs {
			if _, ok := order[fmt.Sprint(v)]; ok {
				slots = append(slots, i)
				members = append(members, fmt.Sprint(v))
			}
		}
		// Small per-group stable insertion sort leaves builtins and nested groups in place.
		for i := 1; i < len(members); i++ {
			for j := i; j > 0 && order[members[j]] < order[members[j-1]]; j-- {
				members[j], members[j-1] = members[j-1], members[j]
			}
		}
		for i, slot := range slots {
			refs[slot] = members[i]
		}
		group["proxies"] = refs
	}
	return nil
}
