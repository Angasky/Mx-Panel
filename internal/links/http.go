package links

import (
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func httpText(value string) bool {
	return len(value) <= 8192 && !strings.ContainsFunc(value, unicode.IsControl)
}

func parseHTTP(u *url.URL, scheme string) (map[string]any, error) {
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrURI
	}
	for _, pair := range [][2]string{{"allowInsecure", "insecure"}, {"skip-cert-verify", "insecure"}, {"ua", "user-agent"}} {
		alias, key := pair[0], pair[1]
		if values, exists := q[alias]; exists {
			if len(values) != 1 {
				return nil, ErrURI
			}
			if original, exists := q[key]; exists && (len(original) != 1 || original[0] != values[0]) {
				return nil, ErrURI
			}
			q.Set(key, values[0])
			q.Del(alias)
		}
	}
	for key, values := range q {
		switch key {
		case "sni", "fingerprint", "name-cert-verify", "host", "user-agent", "insecure", "tls", "security", "udp":
		default:
			return nil, ErrURI
		}
		if len(values) != 1 || !httpText(values[0]) {
			return nil, ErrURI
		}
	}
	port := 80
	if scheme == "https" {
		port = 443
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, ErrURI
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, ErrURI
	}
	node := map[string]any{"type": "http", "server": u.Hostname(), "port": port, "name": u.Fragment, "udp": false}
	if node["name"] == "" {
		node["name"] = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	}
	tls := scheme == "https"
	if q.Has("security") {
		if q.Get("security") != "tls" {
			return nil, ErrURI
		}
		tls = true
	}
	for _, key := range []string{"tls", "insecure", "udp"} {
		if !q.Has(key) {
			continue
		}
		raw := q.Get(key)
		if raw != "true" && raw != "false" && raw != "1" && raw != "0" {
			return nil, ErrURI
		}
		b := raw == "true" || raw == "1"
		switch key {
		case "tls":
			if !b && tls {
				return nil, ErrURI
			}
			tls = b
		case "insecure":
			node["skip-cert-verify"] = b
		case "udp":
			if b {
				return nil, ErrURI
			}
		}
	}
	if tls {
		node["tls"] = true
	}
	if u.User != nil {
		node["username"] = u.User.Username()
		if password, ok := u.User.Password(); ok {
			node["password"] = password
		}
	}
	for _, key := range []string{"sni", "fingerprint", "name-cert-verify"} {
		if q.Has(key) {
			value := q.Get(key)
			if !tls || value == "" {
				return nil, ErrURI
			}
			if key == "fingerprint" {
				value, err = normalizePin(value)
				if err != nil {
					return nil, err
				}
			}
			node[key] = value
		}
	}
	if !tls && q.Has("insecure") {
		return nil, ErrURI
	}
	headers := map[string]any{}
	for query, key := range map[string]string{"host": "Host", "user-agent": "User-Agent"} {
		if q.Has(query) {
			headers[key] = q.Get(query)
		}
	}
	if len(headers) > 0 {
		node["headers"] = headers
	}
	return node, nil
}

func exportHTTP(n map[string]any) (string, error) {
	// A share URL has no representation for arbitrary headers or additional
	// transport settings. Never silently drop them when sharing a YAML node.
	allowed := map[string]bool{}
	for _, key := range []string{"name", "type", "server", "port", "username", "password", "tls", "udp", "skip-cert-verify", "sni", "servername", "fingerprint", "name-cert-verify", "headers"} {
		allowed[key] = true
	}
	for key := range n {
		if !allowed[key] {
			return "", ErrURI
		}
	}
	for _, key := range []string{"tls", "udp", "skip-cert-verify"} {
		if raw, exists := n[key]; exists {
			if _, ok := raw.(bool); !ok {
				return "", ErrURI
			}
		}
	}
	if n["udp"] == true {
		return "", ErrURI
	}
	tls := n["tls"] == true
	scheme := "http"
	if tls {
		scheme = "https"
	}
	port, err := strconv.Atoi(text(n["port"]))
	if err != nil || port < 1 || port > 65535 || text(n["server"]) == "" {
		return "", ErrURI
	}
	u := url.URL{Scheme: scheme, Host: net.JoinHostPort(text(n["server"]), strconv.Itoa(port)), Fragment: text(n["name"])}
	user, userExists := n["username"]
	password, passwordExists := n["password"]
	if userExists || passwordExists {
		username := ""
		if userExists {
			var ok bool
			username, ok = user.(string)
			if !ok {
				return "", ErrURI
			}
		}
		if passwordExists {
			value, ok := password.(string)
			if !ok {
				return "", ErrURI
			}
			u.User = url.UserPassword(username, value)
		} else {
			u.User = url.User(username)
		}
	}
	q := url.Values{}
	for _, key := range []string{"sni", "servername", "fingerprint", "name-cert-verify"} {
		raw, exists := n[key]
		if !exists {
			continue
		}
		value, ok := raw.(string)
		if !ok || value == "" || !httpText(value) || !tls {
			return "", ErrURI
		}
		if key == "fingerprint" {
			value, err = normalizePin(value)
			if err != nil {
				return "", err
			}
		}
		query := key
		if key == "servername" {
			query = "sni"
		}
		if q.Has(query) && q.Get(query) != value {
			return "", ErrURI
		}
		q.Set(query, value)
	}
	if raw, exists := n["skip-cert-verify"]; exists {
		if !tls {
			return "", ErrURI
		}
		q.Set("skip-cert-verify", strconv.FormatBool(raw.(bool)))
	}
	if raw, exists := n["headers"]; exists {
		headers, ok := raw.(map[string]any)
		if !ok {
			return "", ErrURI
		}
		for header, raw := range headers {
			query := ""
			switch strings.ToLower(header) {
			case "host":
				query = "host"
			case "user-agent":
				query = "user-agent"
			default:
				return "", ErrURI
			}
			value, ok := raw.(string)
			if !ok || !httpText(value) || q.Has(query) {
				return "", ErrURI
			}
			q.Set(query, value)
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
