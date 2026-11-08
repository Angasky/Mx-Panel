package subscriptions

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

// A deliberately conservative INI dialect: never interpolate unescaped separators
// or silently drop unsupported node options. Original rules and groups are not copied.
func surgeAtom(value string) bool {
	return value != "" && !strings.Contains(value, "//") && utf8.ValidString(value) && strings.TrimSpace(value) == value && !strings.ContainsAny(value, ",;#\"'\\[]") && !strings.ContainsFunc(value, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) || r == 0x2028 || r == 0x2029 })
}
func surgeNode(node Record) (string, error) {
	kind := text(node["type"])
	if node["client-fingerprint"] != nil {
		return "", errors.New("Surge 无对应的客户端 TLS 指纹选项；需另建未启用指纹的兼容节点，或使用 Mihomo 原始配置")
	}
	if node["dialer-proxy"] != nil {
		return "", errors.New("链式代理请使用完整 Mihomo 配置，当前 Surge 导出不转换链路")
	}
	allowed := map[string]bool{"name": true, "type": true, "server": true, "port": true, "tfo": true, "udp": true}
	fields := []string{}
	tls := false
	switch kind {
	case "ss":
		fields = []string{"cipher", "password"}
	case "trojan":
		fields = []string{"password", "sni", "servername", "skip-cert-verify", "network", "tls"}
		tls = true
	case "http", "socks5":
		fields = []string{"username", "password", "tls", "sni", "servername", "skip-cert-verify"}
	case "snell":
		fields = []string{"psk", "version", "reuse", "obfs-opts"}
	default:
		return "", errors.New("此协议尚未适配 Surge 导出")
	}
	for _, key := range fields {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return "", errors.New("节点含未适配的扩展参数，请使用原始 Mihomo 配置")
		}
	}
	for _, key := range []string{"name", "type", "server", "password", "username", "cipher", "psk", "sni", "servername", "network"} {
		if v, exists := node[key]; exists {
			if _, ok := v.(string); !ok {
				return "", errors.New("节点文本参数类型无效")
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
		return "", errors.New("节点参数未通过兼容性校验，请使用原始 Mihomo 配置")
	}
	host := text(node["server"])
	if net.ParseIP(strings.Trim(host, "[]")) != nil {
		host = strings.Trim(host, "[]")
	}
	if !surgeAtom(host) || strings.ContainsAny(host, " =/@\t") {
		return "", errors.New("服务器地址无法安全写入 Surge 配置")
	}
	port, e := strconv.Atoi(text(node["port"]))
	if e != nil || port < 1 || port > 65535 {
		return "", errors.New("节点端口无效")
	}
	for _, key := range []string{"tfo", "udp", "tls", "skip-cert-verify", "reuse"} {
		if value, exists := node[key]; exists {
			if _, ok := value.(bool); !ok {
				return "", errors.New("节点开关参数类型无效")
			}
		}
	}
	if node["tls"] == true {
		tls = true
	}
	proxyKind := kind
	if kind == "http" && tls {
		proxyKind = "https"
	}
	if kind == "socks5" && tls {
		proxyKind = "socks5-tls"
	}
	params := []string{proxyKind, host, strconv.Itoa(port)}
	add := func(key, value string) error {
		if !surgeAtom(value) {
			return errors.New("节点参数含配置分隔符或控制字符，不能无损导出")
		}
		params = append(params, key+"="+value)
		return nil
	}
	switch kind {
	case "ss":
		cipher := text(node["cipher"])
		supported := map[string]bool{"aes-128-gcm": true, "aes-192-gcm": true, "aes-256-gcm": true, "chacha20-ietf-poly1305": true, "xchacha20-ietf-poly1305": true, "2022-blake3-aes-128-gcm": true, "2022-blake3-aes-256-gcm": true}
		if !supported[cipher] {
			return "", errors.New("此 Shadowsocks 加密方式尚未适配 Surge 导出")
		}
		if e = add("encrypt-method", cipher); e != nil {
			return "", e
		}
		if e = add("password", text(node["password"])); e != nil {
			return "", e
		}
	case "trojan":
		if node["tls"] == false {
			return "", errors.New("Trojan 必须使用 TLS")
		}
		if network := text(node["network"]); network != "" && network != "tcp" {
			return "", errors.New("当前 Surge 导出仅支持 Trojan TCP/TLS 传输")
		}
		if node["udp"] == false {
			return "", errors.New("Surge Trojan 自动启用 UDP，无法保留显式禁用 UDP 的设置")
		}
		if e = add("password", text(node["password"])); e != nil {
			return "", e
		}
	case "http", "socks5":
		if kind == "http" && node["udp"] == true {
			return "", errors.New("HTTP/HTTPS 代理不支持 UDP")
		}
		for _, key := range []string{"username", "password"} {
			if value := text(node[key]); value != "" {
				if e = add(key, value); e != nil {
					return "", e
				}
			}
		}
	case "snell":
		normalized, e := links.NormalizeSnell(node)
		if e != nil {
			return "", errors.New("Snell 参数无效")
		}
		version, e := strconv.Atoi(text(normalized["version"]))
		if e != nil || version < 1 || version > 5 {
			return "", errors.New("当前仅适配 Snell v1–v5")
		}
		if version >= 3 && node["udp"] == false {
			return "", errors.New("Surge Snell v3+ 自动启用 UDP，无法保留禁用设置")
		}
		if e = add("psk", text(normalized["psk"])); e != nil {
			return "", e
		}
		params = append(params, "version="+strconv.Itoa(version))
		if value, exists := node["reuse"]; exists {
			if version < 4 {
				return "", errors.New("当前仅为 Snell v4+ 映射 reuse 参数")
			}
			params = append(params, fmt.Sprintf("reuse=%t", value))
		}
		if value, exists := node["obfs-opts"]; exists {
			obfs, ok := value.(map[string]any)
			if !ok {
				return "", errors.New("Snell 混淆配置无效")
			}
			for key := range obfs {
				if key != "mode" && key != "host" {
					return "", errors.New("Snell 混淆参数尚未适配")
				}
			}
			mode := text(obfs["mode"])
			if mode != "http" && mode != "tls" || version >= 4 && mode != "http" {
				return "", errors.New("Snell 版本与混淆方式不兼容")
			}
			if e = add("obfs", mode); e != nil {
				return "", e
			}
			if host := text(obfs["host"]); host != "" {
				if e = add("obfs-host", host); e != nil {
					return "", e
				}
			}
		}
	}
	if tls {
		sni := text(node["sni"])
		alternate := text(node["servername"])
		if sni != "" && alternate != "" && sni != alternate {
			return "", errors.New("SNI 与 servername 不一致")
		}
		if sni == "" {
			sni = alternate
		}
		if strings.EqualFold(sni, "off") {
			return "", errors.New("Surge 将 SNI off 解释为关闭 SNI，无法保留该名称")
		}
		if sni != "" {
			if e = add("sni", sni); e != nil {
				return "", e
			}
		}
		if value, exists := node["skip-cert-verify"]; exists {
			params = append(params, fmt.Sprintf("skip-cert-verify=%t", value))
		}
	} else if node["sni"] != nil || node["servername"] != nil {
		return "", errors.New("非 TLS 节点不能映射 SNI")
	} else if _, exists := node["skip-cert-verify"]; exists {
		return "", errors.New("非 TLS 节点不能映射证书校验选项")
	}
	if value, exists := node["tfo"]; exists {
		params = append(params, fmt.Sprintf("tfo=%t", value))
	}
	if kind == "ss" || kind == "socks5" {
		if value, exists := node["udp"]; exists {
			params = append(params, fmt.Sprintf("udp-relay=%t", value))
		}
	}
	return strings.Join(params, ", "), nil
}
func convertSurge(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	rows := []string{}
	names := []string{}
	for i, node := range objects(source.Document["proxies"]) {
		proxy, err := surgeNode(node)
		if err != nil {
			result.Skipped = append(result.Skipped, Record{"name": node["name"], "type": node["type"], "reason": err.Error()})
			continue
		}
		name := fmt.Sprintf("MX-%d ", i+1) + strings.TrimPrefix(shadowrocketName(text(node["name"]), strconv.Itoa(i), false), "MX-N-")
		name = strings.ReplaceAll(name, "/", " ")
		rows = append(rows, name+" = "+proxy)
		names = append(names, name)
	}
	result.Count = len(rows)
	if result.Count == 0 {
		return result, errors.New("没有可转换的 Surge 兼容节点")
	}
	result.Body = []byte("# MXIOC Surge profile: manual selection; original Mihomo rules/groups are not included.\n[Proxy]\n" + strings.Join(rows, "\n") + "\n\n[Proxy Group]\nMX-PROXY = select, " + strings.Join(names, ", ") + "\n\n[Rule]\nFINAL,MX-PROXY\n")
	return result, nil
}
