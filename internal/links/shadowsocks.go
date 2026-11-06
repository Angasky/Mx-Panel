package links

import (
	"encoding/base64"
	"strings"
)

// ValidateSS2022Password checks a single PSK or an AES server:user key pair.
// Longer identity chains are not accepted until supported end to end.
func ValidateSS2022Password(method, password string) error {
	size := 0
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305":
		size = 32
	default:
		return ErrURI
	}
	keys := strings.Split(password, ":")
	if len(keys) > 2 || len(keys) > 1 && method == "2022-blake3-chacha20-poly1305" {
		return ErrURI
	}
	for _, key := range keys {
		decoded, err := base64.StdEncoding.DecodeString(key)
		if err != nil || len(decoded) != size || base64.StdEncoding.EncodeToString(decoded) != key {
			return ErrURI
		}
	}
	return nil
}
