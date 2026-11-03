package remote

import "errors"

// NodeOutbound is shared by complete client configurations and remote relays.
// Unknown options are rejected rather than silently weakening the transport.
func NodeOutbound(node Record, tag string) (Record, error) {
	for _, key := range []string{"tls", "udp", "skip-cert-verify"} {
		if raw, ok := node[key]; ok {
			if _, ok := raw.(bool); !ok {
				return nil, errors.New("TLS 和 UDP 开关必须为布尔值")
			}
		}
	}
	allowed := map[string]bool{}
	for _, k := range []string{"name", "type", "server", "port", "uuid", "password", "username", "cipher", "alterId", "alter-id", "encryption", "flow", "network", "tls", "servername", "sni", "client-fingerprint", "skip-cert-verify", "alpn", "reality-opts", "ws-opts", "grpc-opts", "udp", "tfo"} {
		allowed[k] = true
	}
	for k := range node {
		if !allowed[k] {
			return nil, errors.New("节点扩展参数尚未适配完整 Xray 配置")
		}
	}
	if node["skip-cert-verify"] == true || node["udp"] == false {
		return nil, errors.New("此证书或 UDP 限制不能无损转换为当前 Xray 配置")
	}
	kind := value(node["type"])
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
	network := value(node["network"])
	if network == "" {
		network = "tcp"
	}
	if network != "tcp" && network != "ws" && network != "grpc" {
		return nil, errors.New("Xray 传输仅支持 TCP、WebSocket 和 gRPC")
	}
	if node["ws-opts"] != nil && network != "ws" || node["grpc-opts"] != nil && network != "grpc" {
		return nil, errors.New("传输参数与节点网络类型不一致")
	}
	if value(node["flow"]) != "" && (kind != "vless" || node["tls"] != true || network != "tcp") {
		return nil, errors.New("Vision 要求 VLESS TLS TCP")
	}
	stream := Record{"network": network, "security": "none"}
	if raw := node["reality-opts"]; raw != nil {
		if node["alpn"] != nil {
			return nil, errors.New("Reality ALPN 选项尚未适配")
		}
		opts, err := inboundObject(raw)
		if err != nil {
			return nil, err
		}
		for k := range opts {
			if k != "public-key" && k != "short-id" {
				return nil, errors.New("Reality 扩展参数未适配")
			}
		}
		if kind != "vless" || network != "tcp" || value(opts["public-key"]) == "" {
			return nil, errors.New("Reality 要求 VLESS TCP 和有效公钥")
		}
		fp := value(node["client-fingerprint"])
		if fp == "" {
			fp = "chrome"
		}
		stream["security"] = "reality"
		stream["realitySettings"] = Record{"serverName": value(node["servername"]), "fingerprint": fp, "publicKey": opts["public-key"], "shortId": value(opts["short-id"]), "spiderX": "/"}
	} else if node["tls"] == true {
		sni := value(node["servername"])
		if sni == "" {
			sni = value(node["sni"])
		}
		tls := Record{"serverName": sni}
		if node["alpn"] != nil {
			values, ok := node["alpn"].([]any)
			if !ok {
				return nil, errors.New("ALPN 必须为字符串数组")
			}
			for _, v := range values {
				if _, ok := v.(string); !ok {
					return nil, errors.New("ALPN 必须为字符串数组")
				}
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
