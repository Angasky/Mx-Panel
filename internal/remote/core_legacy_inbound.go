package remote

import (
	"errors"
	"maps"
	"net"
	"strconv"
)

var invalidCoreInbound = errors.New("invalid legacy core inbound")

// legacyNativeInbound reconstructs the exact inbound written by the Python
// adapter. An exact match is required before treating local metadata as live.
func legacyNativeInbound(kind string, row Record) (Record, error) {
	settings, err := object(row["settings"])
	if err != nil || row["settings"] == nil {
		return nil, invalidCoreInbound
	}
	stream, err := object(row["streamSettings"])
	if err != nil {
		return nil, err
	}
	var clients []any
	if raw, exists := settings["clients"]; exists {
		items, ok := raw.([]any)
		if !ok {
			return nil, invalidCoreInbound
		}
		clients = []any{}
		for _, item := range items {
			client, ok := item.(map[string]any)
			if !ok {
				return nil, invalidCoreInbound
			}
			if client["enable"] != false {
				clients = append(clients, client)
			}
		}
	}
	protocol, listen := value(row["protocol"]), value(row["listen"])
	if kind == "xray" {
		if listen == "" {
			listen = "0.0.0.0"
		}
		if clients != nil {
			settings = maps.Clone(settings)
			settings["clients"] = clients
			if protocol == "hysteria" {
				settings["users"] = clients
				delete(settings, "clients")
			}
		}
		sniffing, err := object(row["sniffing"])
		if err != nil {
			return nil, err
		}
		return Record{"tag": row["tag"], "listen": listen, "port": row["port"], "protocol": protocol,
			"settings": settings, "streamSettings": stream, "sniffing": sniffing}, nil
	}
	if kind != "sing-box" {
		return nil, invalidCoreInbound
	}
	if listen == "" {
		listen = "::"
	}
	native := Record{"type": protocol, "tag": row["tag"], "listen": listen, "listen_port": row["port"]}
	switch protocol {
	case "shadowsocks":
		if value(settings["method"]) == "" || value(settings["password"]) == "" {
			return nil, invalidCoreInbound
		}
		native["method"], native["password"] = settings["method"], settings["password"]
	case "vless", "vmess", "trojan", "hysteria2", "tuic":
		users := []any{}
		for _, raw := range clients {
			client := raw.(Record)
			name, ok := client["email"]
			if !ok {
				name = value(client["id"])
			}
			user := Record{"name": name}
			if protocol != "trojan" && protocol != "hysteria2" {
				if value(client["id"]) == "" {
					return nil, invalidCoreInbound
				}
				user["uuid"] = client["id"]
			}
			if protocol == "trojan" || protocol == "hysteria2" || protocol == "tuic" {
				if value(client["password"]) == "" {
					return nil, invalidCoreInbound
				}
				user["password"] = client["password"]
			}
			if value(client["flow"]) != "" {
				user["flow"] = client["flow"]
			}
			users = append(users, user)
		}
		native["users"] = users
	default:
		return nil, invalidCoreInbound
	}
	tls, err := legacySingTLS(stream)
	if err != nil {
		return nil, err
	}
	if tls != nil {
		native["tls"] = tls
	}
	switch value(stream["network"]) {
	case "", "tcp":
	case "ws", "grpc":
		network := value(stream["network"])
		options, err := object(stream[network+"Settings"])
		if err != nil {
			return nil, err
		}
		key, field, fallback := "path", "path", "/"
		if network == "grpc" {
			key, field, fallback = "serviceName", "service_name", ""
		}
		setting, exists := options[key]
		if !exists {
			setting = fallback
		}
		native["transport"] = Record{"type": network, field: setting}
	default:
		return nil, invalidCoreInbound
	}
	return native, nil
}

func legacySingTLS(stream Record) (Record, error) {
	switch value(stream["security"]) {
	case "", "none":
		return nil, nil
	case "tls":
		settings, err := object(stream["tlsSettings"])
		if err != nil {
			return nil, err
		}
		certs, _ := settings["certificates"].([]any)
		if len(certs) == 0 {
			return nil, invalidCoreInbound
		}
		cert, err := object(certs[0])
		if err != nil || value(cert["certificateFile"]) == "" || value(cert["keyFile"]) == "" {
			return nil, invalidCoreInbound
		}
		tls := Record{"enabled": true, "server_name": value(settings["serverName"]), "certificate_path": cert["certificateFile"], "key_path": cert["keyFile"]}
		if alpn, _ := settings["alpn"].([]any); len(alpn) != 0 {
			tls["alpn"] = alpn
		}
		return tls, nil
	case "reality":
		r, err := object(stream["realitySettings"])
		if err != nil {
			return nil, err
		}
		target := value(r["target"])
		if target == "" {
			target = value(r["dest"])
		}
		host, portText, err := net.SplitHostPort(target)
		names, _ := r["serverNames"].([]any)
		ids, _ := r["shortIds"].([]any)
		if err != nil || host == "" || len(names) == 0 || value(names[0]) == "" || ids == nil || value(r["privateKey"]) == "" {
			return nil, invalidCoreInbound
		}
		port, err := strconv.Atoi(portText)
		if err != nil || port < 1 || port > 65535 {
			return nil, invalidCoreInbound
		}
		return Record{"enabled": true, "server_name": names[0], "reality": Record{
			"enabled": true, "private_key": r["privateKey"], "short_id": ids,
			"handshake": Record{"server": host, "server_port": port},
		}}, nil
	default:
		return nil, invalidCoreInbound
	}
}
