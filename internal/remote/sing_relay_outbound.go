package remote

import (
	"errors"
	"maps"
	"strconv"
	"strings"
)

func singRelayOutbound(node Record, tag string) (Record, error) {
	if node["network"] == "xhttp" {
		return nil, errors.New("当前 sing-box 中转不支持 XHTTP 落地")
	}
	kind := value(node["type"])
	if kind == "hysteria2" || kind == "tuic" {
		return singQUICRelayOutbound(node, tag, kind)
	}
	checked, err := NodeOutbound(node, tag)
	if err != nil {
		return nil, err
	}
	protocol := value(checked["protocol"])
	next := Record{"type": protocol, "tag": tag, "server": node["server"], "server_port": node["port"]}
	switch kind {
	case "vless":
		next["uuid"] = node["uuid"]
		if value(node["flow"]) != "" {
			next["flow"] = node["flow"]
		}
	case "vmess":
		next["uuid"], next["security"] = node["uuid"], "auto"
		if value(node["cipher"]) != "" {
			next["security"] = node["cipher"]
		}
	case "trojan", "ss":
		next["password"] = node["password"]
		if kind == "ss" {
			next["method"] = node["cipher"]
		}
	case "socks5", "http":
		if kind == "socks5" {
			next["version"] = "5"
		}
		if node["username"] != nil {
			next["username"], next["password"] = value(node["username"]), value(node["password"])
		}
	}
	stream := checked["streamSettings"].(Record)
	switch stream["security"] {
	case "tls":
		tls := stream["tlsSettings"].(Record)
		next["tls"] = singRelayTLS(tls, tls["serverName"])
	case "reality":
		reality := stream["realitySettings"].(Record)
		tls := singRelayTLS(reality, reality["serverName"])
		tls["reality"] = Record{"enabled": true, "public_key": reality["publicKey"], "short_id": reality["shortId"]}
		next["tls"] = tls
	}
	switch stream["network"] {
	case "ws", "grpc":
		if kind != "vless" && kind != "vmess" && kind != "trojan" {
			return nil, errors.New("该 sing-box 出站协议不支持此传输方式")
		}
		if stream["network"] == "ws" {
			ws := stream["wsSettings"].(Record)
			headers, err := object(ws["headers"])
			if err != nil {
				return nil, err
			}
			headers = maps.Clone(headers)
			for name, header := range headers {
				if strings.EqualFold(name, "Host") && header == "" {
					delete(headers, name)
				}
			}
			next["transport"] = Record{"type": "ws", "path": ws["path"], "headers": headers}
		} else {
			grpc := stream["grpcSettings"].(Record)
			next["transport"] = Record{"type": "grpc", "service_name": grpc["serviceName"]}
		}
	}
	if next["tls"] != nil && kind != "vless" && kind != "vmess" && kind != "trojan" && kind != "http" {
		return nil, errors.New("该 sing-box 出站协议不支持此 TLS 配置")
	}
	if node["tfo"] != nil {
		next["tcp_fast_open"] = node["tfo"]
	}
	return next, nil
}

func singRelayTLS(options Record, name any) Record {
	tls := Record{"enabled": true}
	if value(name) != "" {
		tls["server_name"] = name
	}
	if options["alpn"] != nil {
		tls["alpn"] = options["alpn"]
	}
	if value(options["fingerprint"]) != "" {
		tls["utls"] = Record{"enabled": true, "fingerprint": options["fingerprint"]}
	}
	return tls
}

func singQUICRelayOutbound(node Record, tag, kind string) (Record, error) {
	port, err := parsedPort(node["port"], 0)
	if err != nil || port < 1 || !validHost(value(node["server"])) || tag == "" {
		return nil, errors.New("落地地址或端口无效")
	}
	for key := range node {
		switch key {
		case "name", "type", "server", "port", "password", "tls", "sni", "alpn":
		case "skip-cert-verify":
			if node[key] != false {
				return nil, errors.New("中转落地节点必须校验证书")
			}
		case "udp":
			if node[key] != true {
				return nil, errors.New("此 QUIC 落地节点的 UDP 限制尚未适配")
			}
		case "uuid", "congestion-controller", "udp-relay-mode":
			if kind != "tuic" {
				return nil, errors.New("Hysteria2 落地节点包含不适用的 TUIC 参数")
			}
		case "obfs", "obfs-password", "up", "down":
			if kind != "hysteria2" {
				return nil, errors.New("TUIC 落地节点包含不适用的 Hysteria2 参数")
			}
		default:
			return nil, errors.New("QUIC 落地节点包含未适配的扩展参数")
		}
	}
	if node["tls"] != true || value(node["password"]) == "" {
		return nil, errors.New("QUIC 落地节点需要 TLS 和认证密码")
	}
	next := Record{"type": kind, "tag": tag, "server": node["server"], "server_port": port,
		"password": node["password"], "tls": singRelayTLS(node, node["sni"])}
	if kind == "tuic" {
		if value(node["uuid"]) == "" {
			return nil, errors.New("TUIC 落地节点缺少 UUID")
		}
		next["uuid"] = node["uuid"]
		if node["congestion-controller"] != nil {
			next["congestion_control"] = node["congestion-controller"]
		}
		if node["udp-relay-mode"] != nil {
			next["udp_relay_mode"] = node["udp-relay-mode"]
		}
	} else {
		if node["obfs"] != nil {
			next["obfs"] = Record{"type": node["obfs"], "password": node["obfs-password"]}
		}
		for _, direction := range []string{"up", "down"} {
			if raw := value(node[direction]); raw != "" {
				n, err := strconv.Atoi(raw)
				if err != nil || n < 1 {
					return nil, errors.New("Hysteria2 带宽必须是以 Mbps 为单位的正整数")
				}
				next[direction+"_mbps"] = n
			}
		}
	}
	return next, nil
}
