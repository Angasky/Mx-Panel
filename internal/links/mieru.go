package links

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var mieruPortPattern = regexp.MustCompile(`^[0-9]{1,5}$`)
var mieruRangePattern = regexp.MustCompile(`^([0-9]{1,5})-([0-9]{1,5})$`)
var mieruBase64Pattern = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)
var mieruHostPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?$`)

func mieruPort(value any) (int, error) {
	switch value.(type) {
	case int, int64, string, json.Number:
	default:
		return 0, errors.New("Mieru 端口必须为 1–65535 的整数")
	}
	raw := text(value)
	if !mieruPortPattern.MatchString(raw) {
		return 0, errors.New("Mieru 端口必须为 1–65535 的整数")
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("Mieru 端口必须为 1–65535 的整数")
	}
	return n, nil
}

// NormalizeMieru returns an independent top-level map and preserves unknown YAML
// extensions. URI export separately refuses fields the simple format cannot carry.
func NormalizeMieru(input map[string]any) (map[string]any, error) {
	node := map[string]any{}
	for k, v := range input {
		node[k] = v
	}
	if raw, ok := node["port-range"]; ok && raw != nil && raw != "" {
		if port := node["port"]; port != nil && port != "" {
			return nil, errors.New("Mieru 的 port 与 port-range 不能同时填写")
		}
		value, ok := raw.(string)
		if !ok {
			return nil, errors.New("Mieru 端口范围格式无效")
		}
		match := mieruRangePattern.FindStringSubmatch(value)
		if match == nil {
			return nil, errors.New("Mieru 端口范围格式无效")
		}
		first, e := mieruPort(match[1])
		last, e2 := mieruPort(match[2])
		if e != nil || e2 != nil || last < first {
			return nil, errors.New("Mieru 端口范围须为 1–65535 内的起始端口-结束端口")
		}
		node["port-range"] = strconv.Itoa(first) + "-" + strconv.Itoa(last)
		delete(node, "port")
	} else {
		port, err := mieruPort(node["port"])
		if err != nil {
			return nil, err
		}
		node["port"] = port
		delete(node, "port-range")
	}
	for _, key := range []string{"username", "password"} {
		v, ok := node[key].(string)
		if !ok || v == "" || len(v) > 64 || !utf8.ValidString(v) || strings.ContainsAny(v, "\x00\r\n") {
			return nil, errors.New("Mieru 用户名和密码均必填，最多 64 个 UTF-8 字节且不能含换行或空字符")
		}
	}
	transport := "TCP"
	if raw, ok := node["transport"]; ok {
		v, ok := raw.(string)
		if !ok {
			return nil, errors.New("Mieru 传输协议仅支持 TCP 或 UDP")
		}
		transport = strings.ToUpper(v)
	}
	if transport != "TCP" && transport != "UDP" {
		return nil, errors.New("Mieru 传输协议仅支持 TCP 或 UDP")
	}
	node["transport"] = transport
	for key, choices := range map[string][]string{"multiplexing": {"MULTIPLEXING_DEFAULT", "MULTIPLEXING_OFF", "MULTIPLEXING_LOW", "MULTIPLEXING_MIDDLE", "MULTIPLEXING_HIGH"}, "handshake-mode": {"HANDSHAKE_DEFAULT", "HANDSHAKE_STANDARD", "HANDSHAKE_NO_WAIT"}} {
		if raw, ok := node[key]; ok {
			value, ok := raw.(string)
			valid := false
			for _, choice := range choices {
				valid = valid || value == choice
			}
			if !ok || !valid {
				return nil, errors.New("Mieru " + key + " 选项无效")
			}
		}
	}
	if raw, ok := node["mtu"]; ok {
		switch raw.(type) {
		case int, int64:
			if text(raw) != "1400" {
				return nil, errors.New("当前 Mihomo Mieru 不支持自定义 MTU，请使用默认 1400")
			}
		default:
			return nil, errors.New("Mieru MTU 必须为整数 1400")
		}
		delete(node, "mtu")
	}
	if raw, ok := node["udp"]; ok {
		if _, ok := raw.(bool); !ok {
			return nil, errors.New("Mieru UDP 转发开关必须为布尔值")
		}
	}
	if raw, ok := node["traffic-pattern"]; ok {
		pattern, ok := raw.(string)
		if !ok || len(pattern) > 65536 || !mieruBase64Pattern.MatchString(pattern) {
			return nil, errors.New("Mieru traffic-pattern 不是有效 Base64")
		}
		if _, err := base64.StdEncoding.DecodeString(pattern); err != nil {
			return nil, errors.New("Mieru traffic-pattern 不是有效 Base64")
		}
	}
	return node, nil
}

func ParseMany(value string) ([]map[string]any, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(strings.ToLower(value), "mierus://") || strings.HasPrefix(strings.ToLower(value), "mieru://") {
		return parseMieru(value)
	}
	node, err := Parse(value)
	if err != nil {
		return nil, err
	}
	return []map[string]any{node}, nil
}

func parseMieru(value string) ([]map[string]any, error) {
	if len(value) > 65536 || !utf8.ValidString(value) {
		return nil, ErrURI
	}
	u, err := url.Parse(value)
	if err != nil {
		return nil, ErrURI
	}
	if !strings.EqualFold(u.Scheme, "mierus") {
		return nil, errors.New("mieru:// 是完整客户端配置，请使用 mierus:// 简单链接或 Mihomo YAML")
	}
	host := u.Hostname()
	if host == "" || len(host) > 253 || net.ParseIP(host) == nil && !mieruHostPattern.MatchString(host) || u.Port() != "" || u.Host != host && u.Host != "["+host+"]" || u.Path != "" && u.Path != "/" {
		return nil, ErrURI
	}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrURI
	}
	allowed := map[string]bool{"profile": true, "mtu": true, "multiplexing": true, "handshake-mode": true, "traffic-pattern": true, "port": true, "protocol": true}
	for key, values := range query {
		if !allowed[key] || key != "port" && key != "protocol" && len(values) != 1 {
			return nil, errors.New("Mieru 链接包含重复或未适配参数")
		}
	}
	profile := query.Get("profile")
	if profile == "" || !utf8.ValidString(profile) || utf8.RuneCountInString(profile) > 200 || strings.ContainsAny(profile, "\x00\r\n") {
		return nil, errors.New("Mieru 链接缺少有效的 profile 名称")
	}
	ports, protocols := query["port"], query["protocol"]
	if len(ports) == 0 || len(ports) > 256 || len(ports) != len(protocols) {
		return nil, errors.New("Mieru port 与 protocol 须一一对应，每条链接最多 256 组")
	}
	name := u.Fragment
	if name == "" {
		name = profile
	}
	if !utf8.ValidString(name) || len(name) > 1024 || strings.ContainsAny(name, "\x00\r\n") {
		return nil, errors.New("Mieru 节点名称无效")
	}
	username, password := "", ""
	if u.User != nil {
		username = u.User.Username()
		password, _ = u.User.Password()
	}
	nodes := make([]map[string]any, 0, len(ports))
	for i, port := range ports {
		node := map[string]any{"type": "mieru", "name": name, "server": host, "username": username, "password": password, "udp": true, "transport": protocols[i]}
		if strings.Contains(port, "-") {
			node["port-range"] = port
		} else {
			node["port"] = port
		}
		for _, key := range []string{"multiplexing", "handshake-mode", "traffic-pattern"} {
			if values, ok := query[key]; ok {
				node[key] = values[0]
			}
		}
		if values, ok := query["mtu"]; ok {
			if values[0] != "1400" {
				return nil, errors.New("当前 Mihomo Mieru 不支持自定义 MTU，请使用默认 1400")
			}
			node["mtu"] = 1400
		}
		normalized, err := NormalizeMieru(node)
		if err != nil {
			return nil, err
		}
		if len(ports) > 1 {
			runes := []rune(name)
			if len(runes) > 160 {
				runes = runes[:160]
			}
			normalized["name"] = string(runes) + " · " + text(normalized["transport"]) + " " + port
		}
		nodes = append(nodes, normalized)
	}
	return nodes, nil
}

func exportMieru(input map[string]any) (string, error) {
	node, err := NormalizeMieru(input)
	if err != nil {
		return "", err
	}
	allowed := map[string]bool{}
	for _, key := range []string{"type", "name", "server", "port", "port-range", "username", "password", "transport", "udp", "multiplexing", "handshake-mode", "traffic-pattern"} {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return "", errors.New("Mieru 扩展参数请使用完整 Mihomo 订阅")
		}
	}
	if node["udp"] == false {
		return "", errors.New("mierus:// 无法表达关闭 UDP 转发，请使用完整 Mihomo 订阅")
	}
	host, name := text(node["server"]), text(node["name"])
	if host == "" || len(host) > 253 || net.ParseIP(host) == nil && !mieruHostPattern.MatchString(host) || name == "" || utf8.RuneCountInString(name) > 200 || !utf8.ValidString(name) || strings.ContainsAny(name, "\x00\r\n") {
		return "", ErrURI
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	port := text(node["port"])
	if node["port-range"] != nil {
		port = text(node["port-range"])
	}
	q := url.Values{"profile": {name}, "port": {port}, "protocol": {text(node["transport"])}}
	for _, key := range []string{"multiplexing", "handshake-mode", "traffic-pattern"} {
		if raw, ok := node[key]; ok {
			q.Set(key, text(raw))
		}
	}
	uri := (&url.URL{Scheme: "mierus", Host: host, User: url.UserPassword(text(node["username"]), text(node["password"])), RawQuery: q.Encode()}).String()
	if len(uri) > 65536 {
		return "", errors.New("Mieru 链接过长，请使用完整 Mihomo 订阅")
	}
	return uri, nil
}
