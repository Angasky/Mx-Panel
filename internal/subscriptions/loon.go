package subscriptions

import (
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

var loonUUID = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// Loon uses positional quoted secrets, not Surge's named password parameters.
// Restrict inputs to a documented subset instead of guessing escaping rules.
func loonNode(node Record) (string, error) {
	kind := text(node["type"])
	allowed := map[string]bool{"name": true, "type": true, "server": true, "port": true, "tfo": true, "udp": true}
	fields := []string{}
	tls := false
	transport := false
	switch kind {
	case "ss":
		fields = []string{"cipher", "password"}
	case "trojan":
		fields = []string{"password", "tls", "network", "ws-opts", "sni", "servername", "skip-cert-verify"}
		tls = true
		transport = true
	case "vmess":
		fields = []string{"uuid", "cipher", "alterId", "tls", "network", "ws-opts", "sni", "servername", "skip-cert-verify"}
		transport = true
	case "vless":
		fields = []string{"uuid", "tls", "network", "ws-opts", "sni", "servername", "skip-cert-verify"}
		transport = true
	case "http":
		fields = []string{"username", "password", "tls", "sni", "servername", "skip-cert-verify"}
	case "hysteria2":
		fields = []string{"password", "sni", "servername", "skip-cert-verify"}
		tls = true
	default:
		return "", errors.New("此协议尚未适配 Loon 导出")
	}
	if node["client-fingerprint"] != nil {
		return "", errors.New("当前 Loon 导出不映射 TLS 客户端指纹，请使用原始 Mihomo 配置或另建兼容节点")
	}
	for _, key := range fields {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return "", errors.New("节点含未适配的扩展参数（例如 Reality、链路、混淆或端口跳跃），请使用原始 Mihomo 配置")
		}
	}
	for _, key := range []string{"name", "type", "server", "password", "username", "cipher", "uuid", "sni", "servername", "network"} {
		if v, exists := node[key]; exists {
			if _, ok := v.(string); !ok {
				return "", errors.New("节点文本参数类型无效")
			}
		}
	}
	for _, key := range []string{"tfo", "udp", "tls", "skip-cert-verify"} {
		if v, exists := node[key]; exists {
			if _, ok := v.(bool); !ok {
				return "", errors.New("节点开关参数类型无效")
			}
		}
	}
	validation := Record{}
	for key, value := range node {
		if key != "tfo" {
			validation[key] = value
		}
	}
	if _, err := links.Export(validation); err != nil {
		return "", errors.New("节点参数未通过兼容性校验")
	}
	host := text(node["server"])
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		host = strings.Trim(host, "[]")
	}
	if !surgeAtom(host) || strings.ContainsAny(host, " =/@") {
		return "", errors.New("服务器地址无法安全写入 Loon 配置")
	}
	port, e := strconv.Atoi(text(node["port"]))
	if e != nil || port < 1 || port > 65535 {
		return "", errors.New("端口无效")
	}
	if node["tls"] == true {
		tls = true
	}
	if kind == "trojan" && node["tls"] == false {
		return "", errors.New("Trojan 必须使用 TLS")
	}
	proxyKind := kind
	if kind == "ss" {
		proxyKind = "Shadowsocks"
	}
	if kind == "hysteria2" {
		proxyKind = "Hysteria2"
	}
	if kind == "http" && tls {
		proxyKind = "https"
	}
	parts := []string{proxyKind, host, strconv.Itoa(port)}
	add := func(key, value string) error {
		if !surgeAtom(value) {
			return errors.New("节点参数含分隔符、空白或控制字符，不能无损导出")
		}
		parts = append(parts, key+"="+value)
		return nil
	}
	secret := func(value string) error {
		if !surgeAtom(value) {
			return errors.New("节点凭据含当前导出尚未适配的字符")
		}
		parts = append(parts, "\""+value+"\"")
		return nil
	}
	switch kind {
	case "ss":
		cipher := text(node["cipher"])
		if cipher != "aes-128-gcm" && cipher != "aes-256-gcm" && cipher != "chacha20-ietf-poly1305" {
			return "", errors.New("此 Shadowsocks 加密方式尚未适配 Loon 导出")
		}
		parts = append(parts, cipher)
		if e = secret(text(node["password"])); e != nil {
			return "", e
		}
	case "trojan", "hysteria2":
		if e = secret(text(node["password"])); e != nil {
			return "", e
		}
	case "vmess", "vless":
		uuid := text(node["uuid"])
		if !loonUUID.MatchString(uuid) {
			return "", errors.New("UUID 格式无效")
		}
		if kind == "vmess" {
			if text(node["cipher"]) != "aes-128-gcm" {
				return "", errors.New("当前 Loon VMess 导出仅适配 aes-128-gcm")
			}
			parts = append(parts, "aes-128-gcm")
		}
		if e = secret(uuid); e != nil {
			return "", e
		}
		if kind == "vmess" {
			alter := int64(0)
			if node["alterId"] != nil {
				var err error
				alter, err = number(node["alterId"], 0)
				if err != nil || alter < 0 || alter > 65535 {
					return "", errors.New("VMess alterId 无效")
				}
			}
			parts = append(parts, fmt.Sprintf("alterId=%d", alter))
		}
	case "http":
		if node["udp"] == true {
			return "", errors.New("HTTP/HTTPS 不支持 UDP")
		}
		user, password := text(node["username"]), text(node["password"])
		if user != "" || password != "" {
			if !surgeAtom(user) {
				return "", errors.New("HTTP 用户名无法无损导出")
			}
			parts = append(parts, user)
			if e = secret(password); e != nil {
				return "", e
			}
		}
	}
	if transport {
		network := text(node["network"])
		if network == "" {
			network = "tcp"
		}
		if network != "tcp" && network != "ws" {
			return "", errors.New("当前 Loon 导出仅适配 TCP 与基础 WebSocket")
		}
		parts = append(parts, "transport="+network)
		if network != "ws" && node["ws-opts"] != nil {
			return "", errors.New("非 WebSocket 节点含 WebSocket 选项")
		}
		if network == "ws" {
			path := "/"
			ws := Record{}
			if v, exists := node["ws-opts"]; exists {
				var ok bool
				ws, ok = v.(map[string]any)
				if !ok {
					return "", errors.New("WebSocket 参数无效")
				}
			}
			for key := range ws {
				if key != "path" && key != "headers" {
					return "", errors.New("WebSocket 高级参数尚未适配")
				}
			}
			if v, exists := ws["path"]; exists {
				var ok bool
				path, ok = v.(string)
				if !ok {
					return "", errors.New("WebSocket 路径无效")
				}
			}
			if !strings.HasPrefix(path, "/") || strings.Contains(path, "?ed=") {
				return "", errors.New("WebSocket 路径或 early-data 尚未适配")
			}
			if e = add("path", path); e != nil {
				return "", e
			}
			if v, exists := ws["headers"]; exists {
				headers, ok := v.(map[string]any)
				if !ok {
					return "", errors.New("WebSocket 请求头无效")
				}
				for key, value := range headers {
					if key != "Host" {
						return "", errors.New("当前仅支持 WebSocket Host 请求头")
					}
					host, ok := value.(string)
					if !ok {
						return "", errors.New("WebSocket Host 无效")
					}
					if e = add("host", host); e != nil {
						return "", e
					}
				}
			}
		}
		if kind == "vmess" || kind == "vless" {
			parts = append(parts, fmt.Sprintf("over-tls=%t", tls))
		}
	}
	sni, alias := text(node["sni"]), text(node["servername"])
	if sni != "" && alias != "" && sni != alias {
		return "", errors.New("SNI 与 servername 不一致")
	}
	if sni == "" {
		sni = alias
	}
	if !tls && (node["sni"] != nil || node["servername"] != nil || node["skip-cert-verify"] != nil) {
		return "", errors.New("非 TLS 节点包含 TLS 参数")
	}
	if tls {
		if sni != "" {
			if e = add("tls-name", sni); e != nil {
				return "", e
			}
		}
		if v, exists := node["skip-cert-verify"]; exists {
			parts = append(parts, fmt.Sprintf("skip-cert-verify=%t", v))
		}
	}
	if v, exists := node["tfo"]; exists {
		parts = append(parts, fmt.Sprintf("fast-open=%t", v))
	}
	if kind != "http" {
		if v, exists := node["udp"]; exists {
			parts = append(parts, fmt.Sprintf("udp=%t", v))
		}
	}
	return strings.Join(parts, ","), nil
}
func convertLoon(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	rows, names := []string{}, []string{}
	for i, node := range objects(source.Document["proxies"]) {
		proxy, e := loonNode(node)
		if e != nil {
			result.Skipped = append(result.Skipped, Record{"name": node["name"], "type": node["type"], "reason": e.Error()})
			continue
		}
		name := fmt.Sprintf("MX-%d ", i+1) + strings.ReplaceAll(strings.TrimPrefix(shadowrocketName(text(node["name"]), strconv.Itoa(i), false), "MX-N-"), "/", " ")
		rows = append(rows, name+" = "+proxy)
		names = append(names, name)
	}
	result.Count = len(rows)
	if result.Count == 0 {
		return result, errors.New("没有可转换的 Loon 兼容节点")
	}
	result.Body = []byte("# MXIOC Loon profile: manual selection; original Mihomo rules/groups are not included.\n[Proxy]\n" + strings.Join(rows, "\n") + "\n\n[Proxy Group]\nMX-PROXY = select," + strings.Join(names, ",") + "\n\n[Rule]\nFINAL,MX-PROXY\n")
	return result, nil
}
