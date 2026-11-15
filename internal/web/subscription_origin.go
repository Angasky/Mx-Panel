package web

import (
	"errors"
	"golang.org/x/net/idna"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

var subscriptionNumericTLD = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

var subscriptionDomainLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// This is an advertised origin only. Never resolve, fetch, or provision it.
// DNS names (including explicit punycode) only; reject IP shorthand interpreted
// differently by browsers, credentials and any URL path/query/fragment.
func normalizeSubscriptionOrigin(value string) (string, error) {
	if value == "" {
		return "", nil
	}
	invalid := errors.New("订阅域名须为 HTTPS 域名地址，可带端口，不可带路径、参数、账号或 IP；国际域名请使用 Punycode")
	if len(value) > 300 || strings.TrimSpace(value) != value || strings.ContainsAny(value, "\\?#%") {
		return "", invalid
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || u.Host == "" || (u.Path != "" && u.Path != "/") {
		return "", invalid
	}
	host := strings.ToLower(u.Hostname())
	if len(host) > 253 || strings.HasSuffix(u.Host, ":") {
		return "", invalid
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return "", invalid
	}
	for _, label := range labels {
		if !subscriptionDomainLabel.MatchString(label) {
			return "", invalid
		}
	}
	// Browsers may interpret a final numeric label as an IPv4 address.
	last := labels[len(labels)-1]
	if subscriptionNumericTLD.MatchString(last) || last == "localhost" || last == "local" || last == "internal" {
		return "", invalid
	}
	if ascii, err := idna.Lookup.ToASCII(host); err != nil || ascii != host {
		return "", invalid
	}
	port := u.Port()
	if port != "" {
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 {
			return "", invalid
		}
		port = strconv.Itoa(n)
	}
	if port == "443" {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return "https://" + host, nil
}
