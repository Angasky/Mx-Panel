package links

import "net/url"

// Normalize legacy Python share-link aliases before the strict allowlist check.
// Conflicting spellings must not silently select a different TLS or transport
// setting. fingerprint means a certificate pin for HTTP, so it is deliberately
// only treated as a client fingerprint for VLESS and Trojan here.
func normalizeQueryAliases(q url.Values, scheme string) error {
	aliases := map[string]string{"allowInsecure": "insecure"}
	if scheme == "tuic" {
		aliases["allow_insecure"] = "insecure"
		aliases["congestion-controller"] = "congestion_control"
		aliases["udp-relay-mode"] = "udp_relay_mode"
	}
	switch scheme {
	case "vless", "trojan", "tuic", "hysteria2":
		aliases["network"] = "type"
		aliases["peer"] = "sni"
		aliases["servername"] = "sni"
		aliases["service_name"] = "serviceName"
	case "socks5":
		aliases["servername"] = "sni"
	}
	if scheme == "vless" || scheme == "trojan" {
		aliases["fingerprint"] = "fp"
	}
	if scheme == "vless" {
		aliases["publicKey"] = "pbk"
		aliases["shortId"] = "sid"
	}
	if scheme == "hysteria2" {
		aliases["obfsPassword"] = "obfs-password"
		aliases["up"] = "upmbps"
		aliases["down"] = "downmbps"
	}
	for alias, canonical := range aliases {
		values, exists := q[alias]
		if !exists {
			continue
		}
		if len(values) != 1 {
			return ErrURI
		}
		if original, exists := q[canonical]; exists {
			if len(original) != 1 || original[0] != values[0] {
				return ErrURI
			}
		} else {
			q.Set(canonical, values[0])
		}
		q.Del(alias)
	}
	return nil
}

func transportDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}
