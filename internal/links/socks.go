package links

import (
	"net"
	"net/url"
	"strconv"
)

func parseSOCKS(u *url.URL) (map[string]any, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrURI
	}
	for _, pair := range [][2]string{{"allowInsecure", "insecure"}, {"skip-cert-verify", "insecure"}, {"servername", "sni"}} {
		if values, exists := q[pair[0]]; exists {
			if len(values) != 1 {
				return nil, ErrURI
			}
			if other, exists := q[pair[1]]; exists && (len(other) != 1 || other[0] != values[0]) {
				return nil, ErrURI
			}
			q.Set(pair[1], values[0])
			q.Del(pair[0])
		}
	}
	for key, values := range q {
		switch key {
		case "sni", "tls", "udp", "insecure", "security":
		default:
			return nil, ErrURI
		}
		if len(values) != 1 || !httpText(values[0]) {
			return nil, ErrURI
		}
	}
	port := 1080
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, ErrURI
		}
	}
	node := map[string]any{"type": "socks5", "name": u.Fragment, "server": u.Hostname(), "port": port, "udp": true}
	if node["name"] == "" {
		node["name"] = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	}
	if u.User != nil {
		node["username"] = u.User.Username()
		if p, ok := u.User.Password(); ok {
			node["password"] = p
		}
	}
	if q.Has("security") {
		if q.Get("security") != "tls" {
			return nil, ErrURI
		}
		node["tls"] = true
	}
	for query, key := range map[string]string{"tls": "tls", "udp": "udp", "insecure": "skip-cert-verify"} {
		if q.Has(query) {
			raw := q.Get(query)
			if raw != "true" && raw != "false" && raw != "1" && raw != "0" {
				return nil, ErrURI
			}
			b := raw == "true" || raw == "1"
			if query == "tls" && !b && node["tls"] == true {
				return nil, ErrURI
			}
			node[key] = b
		}
	}
	if q.Has("sni") {
		if q.Get("sni") == "" || node["tls"] != true {
			return nil, ErrURI
		}
		node["servername"] = q.Get("sni")
	}
	if q.Has("insecure") && node["tls"] != true {
		return nil, ErrURI
	}
	return node, nil
}

func exportSOCKS(node map[string]any) (string, error) {
	allowed := map[string]bool{}
	for _, key := range []string{"name", "type", "server", "port", "username", "password", "tls", "udp", "skip-cert-verify", "servername", "sni"} {
		allowed[key] = true
	}
	for key := range node {
		if !allowed[key] {
			return "", ErrURI
		}
	}
	// Reuse strict credential, port and TLS checks, then restore SOCKS semantics.
	proxy := map[string]any{}
	for key, value := range node {
		if key != "udp" {
			proxy[key] = value
		}
	}
	uri, err := exportHTTP(proxy)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(uri)
	if err != nil {
		return "", ErrURI
	}
	u.Scheme = "socks5"
	q := u.Query()
	if node["tls"] == true {
		q.Set("tls", "true")
	}
	if raw, exists := node["udp"]; exists {
		b, ok := raw.(bool)
		if !ok {
			return "", ErrURI
		}
		q.Set("udp", strconv.FormatBool(b))
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
