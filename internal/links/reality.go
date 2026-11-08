package links

import (
	"encoding/hex"
	"strings"
)

// NormalizeReality preserves the explicit hybrid handshake policy and removes
// legacy empty/null short IDs without converting hexadecimal strings to numbers.
func NormalizeReality(raw any) (map[string]any, error) {
	opts, ok := raw.(map[string]any)
	if !ok {
		return nil, ErrURI
	}
	out := map[string]any{}
	for key, value := range opts {
		switch key {
		case "public-key":
			text, ok := value.(string)
			if !ok || text == "" {
				return nil, ErrURI
			}
			out[key] = text
		case "short-id":
			if value == nil {
				continue
			}
			text, ok := value.(string)
			if !ok {
				return nil, ErrURI
			}
			text = strings.TrimSpace(text)
			if text == "" || strings.EqualFold(text, "null") || strings.EqualFold(text, "none") {
				continue
			}
			if len(text) > 16 || len(text)%2 != 0 {
				return nil, ErrURI
			}
			if _, err := hex.DecodeString(text); err != nil {
				return nil, ErrURI
			}
			out[key] = text
		case "support-x25519mlkem768":
			b, ok := value.(bool)
			if !ok {
				return nil, ErrURI
			}
			out[key] = b
		default:
			return nil, ErrURI
		}
	}
	if out["public-key"] == nil {
		return nil, ErrURI
	}
	return out, nil
}
