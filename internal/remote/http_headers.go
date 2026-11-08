package remote

import (
	"errors"
	"net/textproto"
	"strings"
)

// Keep CONNECT framing and generated credentials under the core's control.
func singHTTPHeaders(raw any) (Record, error) {
	source, ok := raw.(map[string]any)
	if !ok || len(source) > 64 {
		return nil, errors.New("HTTP 请求头须为对象且不超过 64 项")
	}
	result := Record{}
	for name, rawValue := range source {
		if name == "" || len(name) > 256 {
			return nil, errors.New("HTTP 请求头名称无效")
		}
		for _, c := range name {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return nil, errors.New("HTTP 请求头名称无效")
			}
		}
		key := textproto.CanonicalMIMEHeaderKey(name)
		switch key {
		case "Proxy-Authorization", "Authorization", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection", "Upgrade", "Trailer":
			return nil, errors.New("HTTP 中转请求头不能覆盖认证或连接控制字段")
		}
		if _, exists := result[key]; exists {
			return nil, errors.New("HTTP 请求头名称重复")
		}
		value, ok := rawValue.(string)
		if !ok || len(value) > 8192 {
			return nil, errors.New("HTTP 请求头值必须为字符串且不超过 8192 字节")
		}
		for _, c := range value {
			if c < 32 || c == 127 {
				return nil, errors.New("HTTP 请求头值包含控制字符")
			}
		}
		result[key] = value
	}
	return result, nil
}
