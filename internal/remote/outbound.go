package remote

import (
	"errors"
	"maps"
	"net"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

// NodeOutbound is shared by complete client configurations and remote relays.
// Unknown options are rejected rather than silently weakening the transport.
func NodeOutbound(node Record, tag string) (Record, error) {
	return nodeOutbound(node, tag, true)
}

func nodeOutbound(node Record, tag string, xrayPolicy bool) (Record, error) {
	for _, key := range []string{"tls", "udp", "skip-cert-verify"} {
		if raw, ok := node[key]; ok {
			if _, ok := raw.(bool); !ok {
				return nil, errors.New("TLS 和 UDP 开关必须为布尔值")
			}
		}
	}
	sni := ""
	for _, key := range []string{"servername", "sni"} {
		if raw, exists := node[key]; exists {
			name, ok := raw.(string)
			if !ok || strings.ContainsAny(name, "\r\n\x00") {
				return nil, errors.New("TLS 服务器名称必须为有效字符串")
			}
			if name != "" {
				if sni != "" && sni != name {
					return nil, errors.New("TLS 服务器名称参数冲突")
				}
				sni = name
			}
		}
	}
	allowed := map[string]bool{}
	for _, k := range []string{"name", "type", "server", "port", "uuid", "password", "username", "cipher", "alterId", "alter-id", "encryption", "flow", "network", "tls", "servername", "sni", "client-fingerprint", "skip-cert-verify", "alpn", "reality-opts", "ws-opts", "grpc-opts", "xhttp-opts", "udp", "tfo", "headers"} {
		allowed[k] = true
	}
	for k := range node {
		if !allowed[k] {
			return nil, errors.New("节点扩展参数尚未适配完整 Xray 配置")
		}
	}
	kind := value(node["type"])
	// Legacy Python/Mihomo Trojan nodes omit tls: TLS is implicit for this
	// protocol. Use a copy so export never rewrites the stored source node.
	if _, explicit := node["tls"]; kind == "trojan" && !explicit {
		node = maps.Clone(node)
		node["tls"] = true
	}
	// HTTP CONNECT is TCP-only. Its importer explicitly records udp=false;
	// that describes the protocol rather than an unsupported UDP restriction.
	if kind == "http" && node["udp"] == true {
		return nil, errors.New("HTTP CONNECT 出站不支持 UDP")
	}
	if node["skip-cert-verify"] == true {
		return nil, errors.New("当前 Xray 已移除 allowInsecure，无法转换跳过证书校验的节点")
	}
	if node["udp"] == false && kind != "http" {
		return nil, errors.New("此证书或 UDP 限制不能无损转换为当前 Xray 配置")
	}
	var headers Record
	if raw, exists := node["headers"]; exists {
		if kind != "http" {
			return nil, errors.New("HTTP 请求头仅适用于 HTTP 出站")
		}
		var err error
		headers, err = singHTTPHeaders(raw)
		if err != nil {
			return nil, err
		}
		if _, exists := headers["Host"]; exists {
			return nil, errors.New("当前 Xray CONNECT 不支持自定义 Host，请使用 sing-box")
		}
		// Xray evaluates header values as Go templates. Quote literals so imported
		// braces cannot change meaning or interpolate connection metadata.
		for key, header := range headers {
			headers[key] = "{{" + strconv.Quote(header.(string)) + "}}"
		}
	}
	port, err := parsedPort(node["port"], 0)
	host := value(node["server"])
	if err != nil || port < 1 || !validHost(host) || tag == "" {
		return nil, errors.New("出站地址或端口无效")
	}
	settings := Record{}
	protocol := kind
	switch kind {
	case "vless":
		if value(node["uuid"]) == "" {
			return nil, errors.New("VLESS UUID 缺失")
		}
		encryption := value(node["encryption"])
		if encryption == "" {
			encryption = "none"
		}
		if encryption != "none" {
			return nil, errors.New("VLESS 加密参数未适配")
		}
		settings = Record{"address": host, "port": port, "id": node["uuid"], "encryption": encryption, "flow": value(node["flow"])}
	case "vmess":
		if value(node["uuid"]) == "" {
			return nil, errors.New("VMess UUID 缺失")
		}
		cipher := value(node["cipher"])
		if cipher == "" {
			cipher = "auto"
		}
		alter := node["alterId"]
		if alter == nil {
			alter = node["alter-id"]
		}
		if alter == nil {
			alter = 0
		}
		if value(alter) != "0" {
			return nil, errors.New("仅支持现代 VMess AEAD alterId=0")
		}
		settings = Record{"vnext": []any{Record{"address": host, "port": port, "users": []any{Record{"id": node["uuid"], "security": cipher, "alterId": 0}}}}}
	case "trojan", "ss", "socks5", "http":
		endpoint := Record{"address": host, "port": port}
		if kind == "trojan" || kind == "ss" {
			if value(node["password"]) == "" {
				return nil, errors.New("出站密码缺失")
			}
			endpoint["password"] = node["password"]
		}
		if kind == "ss" {
			protocol = "shadowsocks"
			if value(node["cipher"]) == "" {
				return nil, errors.New("Shadowsocks 加密方式缺失")
			}
			if strings.HasPrefix(value(node["cipher"]), "2022-") && links.ValidateSS2022Password(value(node["cipher"]), value(node["password"])) != nil {
				return nil, links.ErrURI
			}
			endpoint["method"] = node["cipher"]
		}
		if kind == "socks5" {
			protocol = "socks"
		}
		if kind == "socks5" || kind == "http" {
			if node["username"] != nil {
				endpoint["users"] = []any{Record{"user": value(node["username"]), "pass": value(node["password"])}}
			}
		}
		settings["servers"] = []any{endpoint}
	default:
		return nil, errors.New("Xray 出站不支持该协议")
	}
	if headers != nil {
		settings["headers"] = headers
	}
	network := value(node["network"])
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "ws" && network != "grpc" && network != "xhttp" {
		return nil, errors.New("当前 Xray 出站传输不受支持")
	}
	if node["ws-opts"] != nil && network != "ws" || node["grpc-opts"] != nil && network != "grpc" || node["xhttp-opts"] != nil && network != "xhttp" {
		return nil, errors.New("传输参数与节点网络类型不一致")
	}
	if value(node["flow"]) != "" && (kind != "vless" || node["tls"] != true || network != "tcp") {
		return nil, errors.New("Vision 要求 VLESS TLS TCP")
	}
	stream := Record{"network": network, "security": "none"}
	if network == "xhttp" {
		if kind != "vless" || node["tls"] != true || node["reality-opts"] != nil {
			return nil, errors.New("当前 XHTTP 出站需要 VLESS 和 TLS")
		}
		opts, err := links.XHTTPOptions(node["xhttp-opts"])
		if err != nil {
			return nil, err
		}
		stream["xhttpSettings"] = opts
	}
	if raw := node["reality-opts"]; raw != nil {
		if node["alpn"] != nil {
			return nil, errors.New("Reality ALPN 选项尚未适配")
		}
		opts, err := inboundObject(raw)
		if err != nil {
			return nil, err
		}
		if kind != "vless" || network != "tcp" || value(opts["public-key"]) == "" {
			return nil, errors.New("Reality 要求 VLESS TCP 和有效公钥")
		}
		fp := value(node["client-fingerprint"])
		if fp == "" {
			fp = "chrome"
		}
		for k, setting := range opts {
			switch k {
			case "public-key", "short-id":
			case "support-x25519mlkem768":
				// Xray negotiates this using its Chrome ClientHello.
				enabled, ok := setting.(bool)
				if !ok || !enabled || fp != "chrome" {
					return nil, errors.New("该 Reality 混合密钥配置不能无损转换为当前 Xray 指纹")
				}
			default:
				return nil, errors.New("Reality 扩展参数未适配")
			}
		}
		stream["security"] = "reality"
		stream["realitySettings"] = Record{"serverName": sni, "fingerprint": fp, "publicKey": opts["public-key"], "shortId": value(opts["short-id"]), "spiderX": "/"}
	} else if node["tls"] == true {
		tls := Record{"serverName": sni}
		if insecure, exists := node["skip-cert-verify"]; exists {
			tls["allowInsecure"] = insecure
		}
		if raw, exists := node["alpn"]; exists {
			values, err := links.ALPNValues(raw, false)
			if err != nil {
				return nil, errors.New("ALPN 必须为有效协议字符串数组")
			}
			tls["alpn"] = values
		}
		if value(node["client-fingerprint"]) != "" {
			tls["fingerprint"] = node["client-fingerprint"]
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = tls
	} else if node["alpn"] != nil || node["client-fingerprint"] != nil || value(node["sni"]) != "" || value(node["servername"]) != "" {
		return nil, errors.New("TLS 参数要求启用 TLS")
	}
	if xrayPolicy && (kind == "vless" || kind == "trojan") && stream["security"] == "none" && !xrayPrivateAddress(host) {
		return nil, errors.New("当前 Xray 禁止公网明文 VLESS/Trojan，请启用 TLS/Reality 或使用支持此配置的内核")
	}
	if network == "ws" {
		opts, e := inboundObject(node["ws-opts"])
		if e != nil {
			return nil, e
		}
		for k := range opts {
			if k != "path" && k != "headers" {
				return nil, errors.New("WebSocket 扩展参数未适配")
			}
		}
		path := value(opts["path"])
		if path == "" {
			path = "/"
		}
		headers := Record{}
		if opts["headers"] != nil {
			headers, e = inboundObject(opts["headers"])
			if e != nil {
				return nil, e
			}
		}
		stream["wsSettings"] = Record{"path": path, "headers": headers}
	}
	if network == "grpc" {
		opts, e := inboundObject(node["grpc-opts"])
		if e != nil {
			return nil, e
		}
		for k := range opts {
			if k != "grpc-service-name" {
				return nil, errors.New("gRPC 扩展参数未适配")
			}
		}
		stream["grpcSettings"] = Record{"serviceName": value(opts["grpc-service-name"])}
	}
	if raw, ok := node["tfo"]; ok {
		v, ok := raw.(bool)
		if !ok {
			return nil, errors.New("TFO 必须为布尔值")
		}
		stream["sockopt"] = Record{"tcpFastOpen": v}
	}
	return Record{"tag": tag, "protocol": protocol, "settings": settings, "streamSettings": stream}, nil
}

// Matches Xray 26.10.31 transport-security exceptions. Do not resolve DNS:
// Xray applies this policy to the configured address, not its resolved IP.
func xrayPrivateAddress(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()
	}
	domain := strings.TrimSuffix(strings.ToLower(host), ".")
	for _, suffix := range []string{"lan", "localdomain", "example", "invalid", "localhost", "test", "local", "home.arpa", "internal"} {
		if domain == suffix || strings.HasSuffix(domain, "."+suffix) {
			return true
		}
	}
	if len(domain) < 1 || len(domain) > 63 || domain[0] < 'a' || domain[0] > 'z' {
		return false
	}
	for i, c := range domain {
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' {
			continue
		}
		if c == '-' && i != len(domain)-1 {
			continue
		}
		return false
	}
	return true
}
