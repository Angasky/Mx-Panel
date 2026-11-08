package remote

import (
	"errors"
	"maps"
	"strings"
	"unicode"
)

func coreProtocolSettings(protocol any) Record {
	settings := Record{"clients": []any{}}
	if protocol == "vless" {
		settings["decryption"] = "none"
	} else if protocol == "vmess" {
		settings["disableInsecureEncryption"] = false
	}
	return settings
}

// Protocol changes require a basic Go-created TLS inbound with no retained
// users or extension settings. Credentials are granted only after reimport.
func editableCoreProtocol(row Record) bool {
	if !protocolTransportCompatible(row) {
		return false
	}
	settings, err := object(row["settings"])
	return err == nil && sameCoreInbound(settings, coreProtocolSettings(row["protocol"]))
}

func prepareCoreProtocol(old, payload Record) (Record, error) {
	raw, exists := payload["protocol"]
	if !exists {
		return old, nil
	}
	if !editableCoreProtocol(old) || (raw != "vless" && raw != "vmess" && raw != "trojan") {
		return nil, errors.New("协议切换仅支持无用户的基础 VLESS / VMess / Trojan TLS 入站，请先解除订阅绑定并清理用户")
	}
	if raw == old["protocol"] {
		return old, nil
	}
	next := maps.Clone(old)
	next["protocol"], next["settings"] = raw, coreProtocolSettings(raw)
	return next, nil
}

// Protocol conversion does not change transport. Permit the supported Host
// and ALPN options without allowing transport switching to discard them.
func protocolTransportCompatible(row Record) bool {
	stream, err := object(row["streamSettings"])
	if err != nil {
		return false
	}
	candidate := maps.Clone(row)
	stream = maps.Clone(stream)
	candidate["streamSettings"] = stream
	if _, ok := managedALPN(row); !ok {
		return false
	}
	tls, err := object(stream["tlsSettings"])
	if err != nil {
		return false
	}
	tls = maps.Clone(tls)
	delete(tls, "alpn")
	stream["tlsSettings"] = tls
	if stream["network"] == "ws" {
		ws, err := object(stream["wsSettings"])
		if err != nil {
			return false
		}
		host, ok := editableWSHost(ws)
		if !ok {
			return false
		}
		// Use the normal editor to validate any retained Host value.
		if err := validateManagedWSHost(host); err != nil {
			return false
		}
		headers, err := object(ws["headers"])
		if err != nil {
			return false
		}
		for key := range headers {
			if !strings.EqualFold(key, "Host") {
				return false
			}
		}
		ws = maps.Clone(ws)
		delete(ws, "headers")
		stream["wsSettings"] = ws
	}
	return editableCoreTransport(candidate)
}

func validateManagedWSHost(host string) error {
	if len(host) > 256 || strings.ContainsAny(host, "/?#@") || strings.ContainsFunc(host, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) {
		return errors.New("WebSocket Host 无效")
	}
	return nil
}
