package links

import (
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// Match Python's legacy host:last-port convention only for a validated IPv6
// host and an explicit decimal port. Never rewrite userinfo, paths or queries.
func normalizeIPv6Authority(uri string) (string, error) {
	prefix, rest, ok := strings.Cut(uri, "://")
	if !ok {
		return "", ErrURI
	}
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	authority, suffix := rest[:end], rest[end:]
	userinfo, endpoint := "", authority
	if at := strings.LastIndexByte(authority, '@'); at >= 0 {
		userinfo, endpoint = authority[:at+1], authority[at+1:]
	}
	if strings.HasPrefix(endpoint, "[") || strings.Count(endpoint, ":") < 2 {
		return uri, nil
	}
	colon := strings.LastIndexByte(endpoint, ':')
	host, port := endpoint[:colon], endpoint[colon+1:]
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Is6() || ip.Zone() != "" || port == "" {
		return "", ErrURI
	}
	for _, r := range port {
		if r < '0' || r > '9' {
			return "", ErrURI
		}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", ErrURI
	}
	return prefix + "://" + userinfo + net.JoinHostPort(host, port) + suffix, nil
}
