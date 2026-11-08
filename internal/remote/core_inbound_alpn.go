package remote

import (
	"errors"
	"maps"
	"strings"
	"unicode"
)

func managedALPN(row Record) (string, bool) {
	if value(row["goCreateKey"]) == "" {
		return "", false
	}
	if row["protocol"] != "vless" && row["protocol"] != "vmess" && row["protocol"] != "trojan" {
		return "", false
	}
	stream, err := object(row["streamSettings"])
	if err != nil || stream["security"] != "tls" {
		return "", false
	}
	switch stream["network"] {
	case "tcp", "ws", "grpc", "xhttp":
	default:
		return "", false
	}
	tls, err := object(stream["tlsSettings"])
	if err != nil {
		return "", false
	}
	if tls["alpn"] == nil {
		return "", true
	}
	raw, ok := tls["alpn"].([]any)
	if !ok {
		return "", false
	}
	values := []string{}
	for _, item := range raw {
		s, ok := item.(string)
		if !ok {
			return "", false
		}
		values = append(values, s)
	}
	text := strings.Join(values, ",")
	if _, err := parseManagedALPN(text, value(stream["network"])); err != nil {
		return "", false
	}
	return text, true
}

func parseManagedALPN(text, network string) ([]any, error) {
	if len(text) > 32 || strings.ContainsFunc(text, unicode.IsControl) {
		return nil, errors.New("ALPN 过长或包含控制字符")
	}
	if text == "" {
		if network == "grpc" || network == "xhttp" {
			return nil, errors.New("gRPC / XHTTP 必须明确包含 h2")
		}
		return nil, nil
	}
	seen := map[string]bool{}
	result := []any{}
	for _, part := range strings.Split(text, ",") {
		item := strings.TrimSpace(part)
		if (item != "h2" && item != "http/1.1") || seen[item] {
			return nil, errors.New("ALPN 仅支持不重复的 h2、http/1.1，以逗号分隔")
		}
		seen[item] = true
		result = append(result, item)
	}
	if (network == "grpc" || network == "xhttp") && !seen["h2"] {
		return nil, errors.New("gRPC / XHTTP 必须包含 h2")
	}
	if network == "grpc" && len(result) != 1 {
		return nil, errors.New("gRPC ALPN 必须为 h2")
	}
	return result, nil
}

func editManagedALPN(row Record, text string) error {
	stream, _ := object(row["streamSettings"])
	alpn, err := parseManagedALPN(text, value(stream["network"]))
	if err != nil {
		return err
	}
	tls, err := object(stream["tlsSettings"])
	if err != nil {
		return err
	}
	stream, tls = maps.Clone(stream), maps.Clone(tls)
	if alpn == nil {
		delete(tls, "alpn")
	} else {
		tls["alpn"] = alpn
	}
	stream["tlsSettings"], row["streamSettings"] = tls, stream
	return nil
}
