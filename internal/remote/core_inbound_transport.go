package remote

import (
	"errors"
	"maps"
)

// Only basic Go-created TLS transports can be switched without losing options.
// Legacy, Reality, Vision and advanced transports keep their existing editor.
func editableCoreTransport(row Record) bool {
	if value(row["goCreateKey"]) == "" || (row["protocol"] != "vless" && row["protocol"] != "vmess") {
		return false
	}
	stream, err := object(row["streamSettings"])
	if err != nil || stream["security"] != "tls" {
		return false
	}
	network := value(stream["network"])
	if network != "tcp" && network != "ws" && network != "grpc" {
		return false
	}
	for key := range stream {
		switch key {
		case "network", "security", "tlsSettings", "tcpSettings", "wsSettings", "grpcSettings":
		default:
			return false
		}
	}
	if tcp, err := object(stream["tcpSettings"]); err != nil || (len(tcp) != 0 && !sameCoreInbound(tcp, Record{"header": Record{"type": "none"}})) {
		return false
	}
	for group, field := range map[string]string{"wsSettings": "path", "grpcSettings": "serviceName"} {
		options, err := object(stream[group])
		if err != nil {
			return false
		}
		for key := range options {
			if key != field {
				return false
			}
		}
		if len(options) != 0 && group != network+"Settings" {
			return false
		}
	}
	tls, err := object(stream["tlsSettings"])
	alpn := Record{"alpn": tls["alpn"]}
	standardALPN := sameCoreInbound(alpn, Record{"alpn": []any{"h2"}}) || sameCoreInbound(alpn, Record{"alpn": []any{"h2", "http/1.1"}})
	if err != nil || (tls["alpn"] != nil && !standardALPN) {
		return false
	}
	settings, err := object(row["settings"])
	if err != nil {
		return false
	}
	if raw, exists := settings["clients"]; exists {
		clients, ok := raw.([]any)
		if !ok || len(anyRecords(raw)) != len(clients) {
			return false
		}
	}
	for _, client := range anyRecords(settings["clients"]) {
		if value(client["flow"]) != "" {
			return false
		}
	}
	return true
}

func prepareCoreTransport(old, payload Record) (Record, error) {
	next := maps.Clone(old)
	raw, changing := payload["network"]
	if !changing {
		return next, nil
	}
	if !editableCoreTransport(old) || (raw != "tcp" && raw != "ws" && raw != "grpc") {
		return nil, errors.New("此托管入站仅支持基础 TCP / WebSocket / gRPC TLS 传输切换")
	}
	stream, _ := object(old["streamSettings"])
	if raw == stream["network"] {
		return next, nil
	}
	stream = maps.Clone(stream)
	for _, group := range []string{"tcpSettings", "wsSettings", "grpcSettings"} {
		delete(stream, group)
	}
	stream["network"] = raw
	switch raw {
	case "tcp":
		stream["tcpSettings"] = Record{"header": Record{"type": "none"}}
	case "ws":
		stream["wsSettings"] = Record{"path": "/"}
	case "grpc":
		stream["grpcSettings"] = Record{"serviceName": "vpn"}
	}
	tls, _ := object(stream["tlsSettings"])
	tls = maps.Clone(tls)
	tls["alpn"] = []any{"h2", "http/1.1"}
	if raw == "grpc" {
		tls["alpn"] = []any{"h2"}
	}
	stream["tlsSettings"], next["streamSettings"] = tls, stream
	return next, nil
}
