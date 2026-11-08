package links

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"net/url"
	"strings"
)

func certificatePin(raw string) (string, error) {
	// Legacy links use commas as PEM line separators. Correctly escaped PEM
	// newlines are accepted as well; unescaped '+' must not corrupt the pin.
	raw = strings.TrimSpace(strings.ReplaceAll(raw, ",", "\n"))
	if !strings.HasPrefix(raw, "-----BEGIN CERTIFICATE-----") {
		return "", ErrURI
	}
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || strings.TrimSpace(string(rest)) != "" {
		return "", ErrURI
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		return "", ErrURI
	}
	sum := sha256.Sum256(block.Bytes)
	return normalizePin(hex.EncodeToString(sum[:]))
}

func normalizePin(raw string) (string, error) {
	compact := raw
	if strings.Contains(raw, ":") {
		parts := strings.Split(raw, ":")
		if len(parts) != sha256.Size {
			return "", ErrURI
		}
		for _, part := range parts {
			if len(part) != 2 {
				return "", ErrURI
			}
		}
		compact = strings.Join(parts, "")
	}
	decoded, err := hex.DecodeString(compact)
	if err != nil || len(decoded) != sha256.Size {
		return "", ErrURI
	}
	parts := make([]string, len(decoded))
	for i, b := range decoded {
		parts[i] = strings.ToUpper(hex.EncodeToString([]byte{b}))
	}
	return strings.Join(parts, ":"), nil
}

func parseCertificatePin(q url.Values, scheme string) (string, error) {
	pin := ""
	for _, key := range []string{"tls_certificate", "tls-certificate", "pinSHA256", "pinned_certchain_sha256"} {
		values, exists := q[key]
		if !exists {
			continue
		}
		if (scheme != "hysteria2" && scheme != "tuic") || len(values) != 1 {
			return "", ErrURI
		}
		var current string
		var err error
		switch key {
		case "tls_certificate", "tls-certificate":
			current, err = certificatePin(values[0])
		case "pinSHA256":
			if scheme != "hysteria2" {
				return "", ErrURI
			}
			current, err = normalizePin(values[0])
		case "pinned_certchain_sha256":
			if scheme != "tuic" {
				return "", ErrURI
			}
			current, err = normalizePin(values[0])
		}
		if err != nil || (pin != "" && pin != current) {
			return "", ErrURI
		}
		pin = current
	}
	return pin, nil
}
