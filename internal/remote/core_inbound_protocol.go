package remote

import (
	"errors"
	"maps"
)

func coreProtocolSettings(protocol any) Record {
	settings := Record{"clients": []any{}}
	if protocol == "vless" {
		settings["decryption"] = "none"
	} else {
		settings["disableInsecureEncryption"] = false
	}
	return settings
}

// Protocol changes require a basic Go-created TLS inbound with no retained
// users or extension settings. Credentials are granted only after reimport.
func editableCoreProtocol(row Record) bool {
	if !editableCoreTransport(row) {
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
	if !editableCoreProtocol(old) || (raw != "vless" && raw != "vmess") {
		return nil, errors.New("协议切换仅支持无用户的基础 VLESS / VMess TLS 入站，请先解除订阅绑定并清理用户")
	}
	if raw == old["protocol"] {
		return old, nil
	}
	next := maps.Clone(old)
	next["protocol"], next["settings"] = raw, coreProtocolSettings(raw)
	return next, nil
}
