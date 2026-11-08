package links

import (
	"strings"
	"unicode"
)

// ALPNValues preserves protocol order. Legacy QUIC YAML permits a single
// string; it is one protocol, not a comma-separated list. Commas are rejected
// because share URIs use them as separators and could not round-trip them.
func ALPNValues(raw any, allowString bool) ([]any, error) {
	var result []any
	switch list := raw.(type) {
	case string:
		if !allowString {
			return nil, ErrURI
		}
		result = []any{list}
	case []string:
		result = make([]any, len(list))
		for i, s := range list {
			result[i] = s
		}
	case []any:
		result = append([]any{}, list...)
	default:
		return nil, ErrURI
	}
	for _, item := range result {
		s, ok := item.(string)
		if !ok || len(s) == 0 || len(s) > 255 || strings.Contains(s, ",") || strings.ContainsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) {
			return nil, ErrURI
		}
	}
	return result, nil
}
