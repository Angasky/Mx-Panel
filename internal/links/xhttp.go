package links

import (
	"strings"
	"unicode"
)

// XHTTPOptions supports the basic settings that can round-trip through
// VLESS URLs, Mihomo YAML and native Xray outbounds.
func XHTTPOptions(raw any) (map[string]any, error) {
	options, ok := raw.(map[string]any)
	if !ok {
		return nil, ErrURI
	}
	path, mode, host := "/", "auto", ""
	for key, raw := range options {
		value, ok := raw.(string)
		if !ok || len(value) > 256 || strings.ContainsFunc(value, func(r rune) bool {
			return unicode.IsSpace(r) || unicode.IsControl(r)
		}) {
			return nil, ErrURI
		}
		switch key {
		case "path":
			if !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") {
				return nil, ErrURI
			}
			path = value
		case "mode":
			switch value {
			case "auto", "stream-up", "packet-up", "stream-one":
				mode = value
			default:
				return nil, ErrURI
			}
		case "host":
			if strings.ContainsAny(value, "/?#@") {
				return nil, ErrURI
			}
			host = value
		default:
			return nil, ErrURI
		}
	}
	result := map[string]any{"path": path, "mode": mode}
	if host != "" {
		result["host"] = host
	}
	return result, nil
}
