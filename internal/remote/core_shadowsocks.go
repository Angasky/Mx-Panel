package remote

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"maps"
	"strings"
)

const ss2022GuardEmail = "mxioc-ss2022-empty-guard"

// The guard is private managed metadata, never a subscription user. Keeping one
// unreachable credential in an otherwise empty native list prevents single-user
// fallback with the server key that is already present in exported client links.
func guardedSS2022Settings(row Record) (Record, error) {
	if _, classic := row["goSSAEADGuard"]; classic {
		return nil, errors.New("Shadowsocks 托管认证模式冲突")
	}
	settings, err := object(row["settings"])
	method := value(settings["method"])
	root, guard := value(settings["password"]), value(row["goSS2022Guard"])
	if err != nil || row["protocol"] != "shadowsocks" || value(row["goCreateKey"]) == "" ||
		!shadowsocks2022Key(method, root, true) || !shadowsocks2022Key(method, guard, true) || root == guard {
		return nil, errors.New("SS2022 托管认证配置无效")
	}
	if _, exists := settings["users"]; exists {
		return nil, errors.New("SS2022 托管用户列表不明确")
	}
	for key := range settings {
		if key != "method" && key != "password" && key != "clients" && !(key == "network" && settings[key] == "tcp,udp") {
			return nil, errors.New("SS2022 托管认证扩展尚未适配")
		}
	}
	clients, ok := settings["clients"].([]any)
	if !ok {
		return nil, errors.New("SS2022 托管用户列表无效")
	}
	seenKeys, seenNames := map[string]bool{root: true, guard: true}, map[string]bool{ss2022GuardEmail: true}
	for _, raw := range clients {
		client, ok := raw.(Record)
		if !ok {
			return nil, errors.New("SS2022 托管用户格式无效")
		}
		key, name := value(client["password"]), value(client["email"])
		if !shadowsocks2022Key(method, key, true) || value(client["method"]) != "" ||
			name == "" || len(name) > 1024 || strings.ContainsAny(name, "\r\n\x00") || strings.Contains(name, ">>>") || seenKeys[key] || seenNames[name] {
			return nil, errors.New("SS2022 托管用户凭据无效或重复")
		}
		seenKeys[key], seenNames[name] = true, true
	}
	stream, err := object(row["streamSettings"])
	if err != nil || (value(stream["security"]) != "" && stream["security"] != "none") ||
		(value(stream["network"]) != "" && stream["network"] != "tcp" && stream["network"] != "raw") {
		return nil, errors.New("SS2022 托管传输尚未适配")
	}
	return settings, nil
}

func ss2022NativeClients(row Record, clients []any) ([]any, error) {
	if _, err := guardedSS2022Settings(row); err != nil {
		return nil, err
	}
	if len(clients) != 0 {
		return clients, nil
	}
	return []any{Record{"email": ss2022GuardEmail, "password": row["goSS2022Guard"]}}, nil
}

func buildStandaloneSS2022Template(payload Record) (Record, error) {
	if name := templateName(payload); name != "ss2022-aes-128" && name != "ss2022-aes-256" {
		return nil, errors.New("SS2022 模板无效")
	}
	base := maps.Clone(payload)
	base["template"] = "vmess-tcp"
	row, err := buildInboundTemplate(base, "")
	if err != nil {
		return nil, err
	}
	method, size := "2022-blake3-aes-128-gcm", 16
	if templateName(payload) == "ss2022-aes-256" {
		method, size = "2022-blake3-aes-256-gcm", 32
	}
	keys := make([]byte, size*2)
	if _, err := rand.Read(keys); err != nil {
		return nil, err
	}
	row["protocol"] = "shadowsocks"
	row["settings"] = Record{"method": method, "password": base64.StdEncoding.EncodeToString(keys[:size]), "network": "tcp,udp", "clients": []any{}}
	row["goSS2022Guard"] = base64.StdEncoding.EncodeToString(keys[size:])
	return row, nil
}
