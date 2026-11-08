package links

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/net/idna"
)

func snellInteger(raw any) (int, error) {
	switch raw.(type) {
	case int, int64, json.Number:
	default:
		return 0, ErrURI
	}
	n, err := strconv.ParseInt(text(raw), 10, 32)
	return int(n), err
}

func snellDomain(raw any) (string, error) {
	value, ok := raw.(string)
	if !ok {
		return "", ErrURI
	}
	value = strings.TrimRight(strings.ToLower(strings.TrimSpace(value)), ".")
	value, err := idna.Lookup.ToASCII(value)
	if err != nil || len(value) > 253 || !strings.Contains(value, ".") {
		return "", ErrURI
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrURI
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return "", ErrURI
			}
		}
	}
	return value, nil
}

// NormalizeSnell preserves YAML extensions and copies every object it modifies.
// Simple links have a separate allowlist to prevent lossy export.
func NormalizeSnell(input map[string]any) (map[string]any, error) {
	node := map[string]any{}
	for key, v := range input {
		node[key] = v
	}
	secret := func(raw any) bool {
		v, ok := raw.(string)
		return ok && v != "" && utf8.ValidString(v) && !strings.ContainsAny(v, "\r\n\x00")
	}
	if !secret(node["psk"]) || len(text(node["psk"])) > 1024 {
		return nil, errors.New("Snell PSK 无效")
	}
	version := 1
	if raw, exists := node["version"]; exists {
		var err error
		version, err = snellInteger(raw)
		if err != nil || version < 1 || version > 5 {
			return nil, errors.New("Snell 版本必须为 1–5")
		}
	}
	node["version"] = version
	for _, key := range []string{"udp", "reuse", "tfo"} {
		if raw, exists := node[key]; exists {
			if _, ok := raw.(bool); !ok {
				return nil, errors.New("Snell 开关必须为布尔值")
			}
		}
	}
	if version < 3 && node["udp"] == true || version < 4 && node["reuse"] == true {
		return nil, errors.New("Snell UDP 需要 v3，reuse 需要 v4 或以上")
	}
	raw := node["obfs-opts"]
	if raw == nil {
		return node, nil
	}
	original, ok := raw.(map[string]any)
	if !ok {
		return nil, errors.New("Snell 混淆配置必须为对象")
	}
	if len(original) == 0 {
		delete(node, "obfs-opts")
		return node, nil
	}
	obfs := map[string]any{}
	for k, v := range original {
		obfs[k] = v
	}
	mode := text(obfs["mode"])
	switch mode {
	case "http", "tls", "shadow-tls", "restls", "jls":
	default:
		return nil, errors.New("Snell 混淆模式无效")
	}
	if raw, exists := obfs["host"]; exists {
		host, err := snellDomain(raw)
		if err != nil {
			return nil, errors.New("Snell 混淆 Host 须为有效域名")
		}
		obfs["host"] = host
	}
	if mode == "shadow-tls" || mode == "restls" || mode == "jls" {
		if text(obfs["host"]) == "" || !secret(obfs["password"]) {
			return nil, errors.New("Snell 高级混淆须填写 Host 和密码")
		}
	}
	if mode == "shadow-tls" {
		v, err := snellInteger(obfs["version"])
		if err != nil || v < 1 || v > 3 {
			return nil, errors.New("ShadowTLS 版本须为 1、2 或 3")
		}
		alpn, err := ALPNValues(obfs["alpn"], false)
		if err != nil || len(alpn) == 0 {
			return nil, errors.New("ShadowTLS ALPN 必须为非空数组")
		}
		for _, p := range alpn {
			if p != "h2" && p != "http/1.1" {
				return nil, errors.New("ShadowTLS ALPN 须为 h2 或 http/1.1")
			}
		}
		obfs["alpn"] = alpn
	}
	if mode == "restls" && obfs["version-hint"] != "tls12" && obfs["version-hint"] != "tls13" {
		return nil, errors.New("Restls version-hint 须为 tls12 或 tls13")
	}
	if mode == "jls" && !secret(obfs["username"]) {
		return nil, errors.New("JLS 混淆必须填写用户名")
	}
	node["obfs-opts"] = obfs
	return node, nil
}
