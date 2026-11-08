// Package links implements native node URI conversion without Python processes.
package links

import (
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

var ErrURI = errors.New("节点链接无效或包含暂未适配的参数")

func text(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case float64:
		return strconv.FormatFloat(n, 'f', -1, 64)
	case json.Number:
		return string(n)
	}
	return ""
}
func decode64(value string) (string, error) {
	for _, encoding := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if decoded, err := encoding.DecodeString(value); err == nil {
			return string(decoded), nil
		}
	}
	return "", ErrURI
}
func Parse(value string) (map[string]any, error) {
	value = strings.TrimSpace(value)
	if len(value) > 65536 {
		return nil, ErrURI
	}
	value = normalizePastedURI(value)
	if name, body, ok := strings.Cut(value, "="); ok && !strings.Contains(name, "://") {
		if kind, _, ok := strings.Cut(body, ","); ok && strings.EqualFold(strings.TrimSpace(kind), "snell") {
			return parseSnellPolicy(value)
		}
	}
	scheme, body, ok := strings.Cut(value, "://")
	if !ok {
		return nil, ErrURI
	}
	scheme = strings.ToLower(scheme)
	if scheme == "mierus" || scheme == "mieru" {
		nodes, err := parseMieru(value)
		if err != nil {
			return nil, err
		}
		if len(nodes) != 1 {
			return nil, errors.New("Mieru 多组端口链接请使用批量导入")
		}
		return nodes[0], nil
	}
	if scheme == "hy2" {
		scheme = "hysteria2"
		value = scheme + "://" + body
	}
	if scheme == "vmess" {
		return parseVMess(body)
	}
	var snellPassword string
	if scheme == "snell" {
		envelope, fragment, hasFragment := strings.Cut(body, "#")
		authority, rest, hasQuery := strings.Cut(envelope, "?")
		query, queryErr := url.ParseQuery(rest)
		if queryErr != nil {
			return nil, ErrURI
		}
		if !strings.Contains(authority, "@") && !query.Has("psk") {
			decoded, err := decode64(authority)
			if err != nil {
				return nil, ErrURI
			}
			at := strings.LastIndex(decoded, "@")
			if at < 0 || !strings.HasPrefix(decoded, "chacha20-ietf-poly1305:") {
				return nil, ErrURI
			}
			snellPassword = strings.TrimPrefix(decoded[:at], "chacha20-ietf-poly1305:")
			value = "snell://" + decoded[at+1:]
			if hasQuery {
				value += "?" + rest
			}
			if hasFragment {
				value += "#" + fragment
			}
		}
	}
	normalized, err := normalizeIPv6Authority(value)
	if err != nil {
		return nil, err
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Hostname() == "" || u.Path != "" && u.Path != "/" {
		return nil, ErrURI
	}
	if scheme == "http" || scheme == "https" {
		return parseHTTP(u, scheme)
	}
	if scheme == "socks" || scheme == "socks5" {
		if strings.HasSuffix(u.Host, ":") {
			return nil, ErrURI
		}
		return parseSOCKS(u)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || port < 1 || port > 65535 {
		return nil, ErrURI
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, ErrURI
	}
	if err := normalizeQueryAliases(q, scheme); err != nil {
		return nil, err
	}
	pin, err := parseCertificatePin(q, scheme)
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, key := range []string{"tls_certificate", "tls-certificate", "pinSHA256", "pinned_certchain_sha256", "support-x25519mlkem768", "encryption", "security", "sni", "alpn", "fp", "flow", "pbk", "sid", "type", "path", "host", "serviceName", "insecure", "allowInsecure", "udp", "reuse", "tfo", "version", "psk", "obfs", "obfs-host", "obfs-password", "upmbps", "downmbps"} {
		allowed[key] = true
	}
	if scheme == "tuic" {
		allowed["password"] = true
	}
	for key, values := range q {
		if (!allowed[key] && key != "congestion_control" && key != "udp_relay_mode" && key != "tls" && key != "mode") || len(values) != 1 {
			return nil, ErrURI
		}
	}
	if q.Get("encryption") != "" && q.Get("encryption") != "none" {
		return nil, ErrURI
	}
	node := map[string]any{"name": u.Fragment, "type": scheme, "server": u.Hostname(), "port": port}
	if pin != "" {
		node["fingerprint"] = pin
	}
	if u.Fragment == "" {
		node["name"] = u.Hostname() + ":" + u.Port()
	}
	credential := ""
	if u.User != nil {
		credential, err = url.PathUnescape(u.User.String())
		if err != nil {
			return nil, ErrURI
		}
	}
	switch scheme {
	case "vless":
		node["uuid"] = credential
	case "trojan":
		node["password"] = credential
	case "hysteria2":
		if u.User == nil {
			return nil, ErrURI
		}
		password, _ := u.User.Password()
		if password == "" {
			password = u.User.Username()
		}
		if password == "" {
			return nil, ErrURI
		}
		node["password"] = password
	case "tuic":
		if u.User == nil {
			return nil, ErrURI
		}
		id := u.User.Username()
		password, _ := u.User.Password()
		if q.Has("password") {
			if password != "" && password != q.Get("password") {
				return nil, ErrURI
			}
			password = q.Get("password")
		}
		if id == "" || password == "" {
			return nil, ErrURI
		}
		node["uuid"] = id
		node["password"] = password
	case "snell":
		allowed := map[string]bool{"psk": true, "version": true, "udp": true, "reuse": true, "tfo": true, "obfs": true, "obfs-host": true}
		for key := range q {
			if !allowed[key] {
				return nil, ErrURI
			}
		}
		if u.User != nil {
			if _, hasPassword := u.User.Password(); hasPassword || q.Has("psk") {
				return nil, ErrURI
			}
		}
		if snellPassword == "" {
			if u.User != nil {
				snellPassword = u.User.Username()
			} else {
				snellPassword = q.Get("psk")
			}
		}
		if snellPassword == "" || len(snellPassword) > 1024 || strings.ContainsAny(snellPassword, "\r\n\x00") {
			return nil, ErrURI
		}
		node["psk"] = snellPassword
		version := 1
		if q.Has("version") {
			v := q.Get("version")
			if len(v) != 1 || v[0] < '1' || v[0] > '5' {
				return nil, ErrURI
			}
			version = int(v[0] - '0')
		}
		node["version"] = version
		for _, key := range []string{"udp", "reuse", "tfo"} {
			if q.Has(key) {
				q.Set(key, strings.ToLower(q.Get(key)))
			}
		}
		if (version < 3 && (q.Get("udp") == "true" || q.Get("udp") == "1")) ||
			(version < 4 && (q.Get("reuse") == "true" || q.Get("reuse") == "1")) {
			return nil, ErrURI
		}
		if q.Has("obfs-host") && !q.Has("obfs") {
			return nil, ErrURI
		}
		if q.Has("obfs") {
			if q.Get("obfs") != "http" && q.Get("obfs") != "tls" {
				return nil, ErrURI
			}
			obfs := map[string]any{"mode": q.Get("obfs")}
			if q.Has("obfs-host") {
				if q.Get("obfs-host") == "" {
					return nil, ErrURI
				}
				obfs["host"] = q.Get("obfs-host")
			}
			node["obfs-opts"] = obfs
		}
	case "ss":
		decoded, err := decode64(credential)
		if err == nil {
			credential = decoded
		}
		cipher, password, ok := strings.Cut(credential, ":")
		if !ok || strings.HasPrefix(cipher, "2022-") && ValidateSS2022Password(cipher, password) != nil {
			return nil, ErrURI
		}
		node["cipher"] = cipher
		node["password"] = password
		if q.Get("plugin") != "" {
			return nil, ErrURI
		}
	case "socks", "socks5", "http", "https":
		if scheme == "socks" {
			node["type"] = "socks5"
		}
		if scheme == "https" {
			node["type"] = "http"
			node["tls"] = true
		}
		if u.User != nil {
			node["username"] = u.User.Username()
			if password, ok := u.User.Password(); ok {
				node["password"] = password
			}
		}
	default:
		return nil, ErrURI
	}
	if scheme == "hysteria2" || scheme == "trojan" || scheme == "tuic" || q.Get("security") == "tls" || q.Get("security") == "reality" {
		node["tls"] = true
	}
	if q.Get("tls") != "" {
		if q.Get("tls") != "true" && q.Get("tls") != "false" && q.Get("tls") != "1" && q.Get("tls") != "0" {
			return nil, ErrURI
		}
		node["tls"] = q.Get("tls") == "true" || q.Get("tls") == "1"
	}
	if pin != "" && node["tls"] != true {
		return nil, ErrURI
	}
	if scheme == "tuic" {
		node["congestion-controller"] = "bbr"
		node["udp-relay-mode"] = "native"
		if q.Get("congestion_control") != "" {
			node["congestion-controller"] = q.Get("congestion_control")
		}
		if q.Get("udp_relay_mode") != "" {
			node["udp-relay-mode"] = q.Get("udp_relay_mode")
		}
	}
	if sni := q.Get("sni"); sni != "" {
		if scheme == "hysteria2" || scheme == "tuic" {
			node["sni"] = sni
		} else {
			node["servername"] = sni
		}
	}
	if scheme == "hysteria2" {
		node["alpn"] = []any{"h3"}
	}
	if q.Get("alpn") != "" {
		values := []any{}
		for _, v := range strings.Split(q.Get("alpn"), ",") {
			values = append(values, v)
		}
		checked, err := ALPNValues(values, false)
		if err != nil {
			return nil, err
		}
		node["alpn"] = checked
	}
	if q.Get("fp") != "" {
		node["client-fingerprint"] = q.Get("fp")
	}
	if q.Get("flow") != "" {
		node["flow"] = q.Get("flow")
	}
	if q.Get("security") == "reality" {
		if q.Get("pbk") == "" {
			return nil, ErrURI
		}
		opts := map[string]any{"public-key": q.Get("pbk"), "short-id": q.Get("sid")}
		if q.Has("support-x25519mlkem768") {
			v := q.Get("support-x25519mlkem768")
			if v != "true" && v != "false" && v != "1" && v != "0" {
				return nil, ErrURI
			}
			opts["support-x25519mlkem768"] = v == "true" || v == "1"
		}
		normalized, err := NormalizeReality(opts)
		if err != nil {
			return nil, err
		}
		node["reality-opts"] = normalized
	}
	if q.Has("support-x25519mlkem768") && (scheme != "vless" || q.Get("security") != "reality" || node["tls"] != true) {
		return nil, ErrURI
	}
	if q.Has("mode") && q.Get("type") != "xhttp" {
		return nil, ErrURI
	}
	if network := q.Get("type"); network != "" && network != "tcp" {
		node["network"] = network
		switch network {
		case "ws":
			headers := map[string]any{}
			if host := q.Get("host"); host != "" {
				headers["Host"] = host
			}
			node["ws-opts"] = map[string]any{"path": transportDefault(q.Get("path"), "/"), "headers": headers}
		case "grpc":
			node["grpc-opts"] = map[string]any{"grpc-service-name": transportDefault(q.Get("serviceName"), "grpc")}
		case "xhttp":
			if scheme != "vless" || q.Get("security") != "tls" || node["tls"] != true || q.Has("flow") || q.Has("serviceName") {
				return nil, ErrURI
			}
			raw := map[string]any{}
			for _, key := range []string{"path", "mode", "host"} {
				if q.Has(key) {
					raw[key] = q.Get(key)
				}
			}
			opts, err := XHTTPOptions(raw)
			if err != nil {
				return nil, err
			}
			node["xhttp-opts"] = opts
		default:
			return nil, ErrURI
		}
	}
	for query, key := range map[string]string{"insecure": "skip-cert-verify", "allowInsecure": "skip-cert-verify", "udp": "udp", "reuse": "reuse", "tfo": "tfo"} {
		if values, ok := q[query]; ok {
			v := values[0]
			if v != "true" && v != "false" && v != "1" && v != "0" {
				return nil, ErrURI
			}
			node[key] = v == "true" || v == "1"
		}
	}
	if scheme == "hysteria2" {
		if q.Get("obfs") != "" {
			if q.Get("obfs") != "salamander" || q.Get("obfs-password") == "" {
				return nil, ErrURI
			}
			node["obfs"] = q.Get("obfs")
			node["obfs-password"] = q.Get("obfs-password")
		}
		if q.Get("upmbps") != "" {
			node["up"] = q.Get("upmbps")
		}
		if q.Get("downmbps") != "" {
			node["down"] = q.Get("downmbps")
		}
	}
	if scheme == "snell" {
		return NormalizeSnell(node)
	}
	return node, nil
}

func parseSnellPolicy(value string) (map[string]any, error) {
	name, body, _ := strings.Cut(value, "=")
	reader := csv.NewReader(strings.NewReader(body))
	reader.TrimLeadingSpace = true
	reader.FieldsPerRecord = -1
	fields, err := reader.Read()
	if err != nil || len(fields) < 3 || !strings.EqualFold(strings.TrimSpace(fields[0]), "snell") {
		return nil, ErrURI
	}
	allowed := map[string]bool{"psk": true, "version": true, "obfs": true, "obfs-host": true, "reuse": true, "udp": true}
	query := url.Values{}
	for _, field := range fields[3:] {
		key, value, ok := strings.Cut(strings.TrimSpace(field), "=")
		if !ok || !allowed[key] || query.Has(key) || strings.HasPrefix(value, "\"") || strings.HasSuffix(value, "\"") || strings.HasPrefix(value, "'") || strings.HasSuffix(value, "'") {
			return nil, ErrURI
		}
		query.Set(key, value)
	}
	if query.Has("obfs-host") && !query.Has("obfs") {
		return nil, ErrURI
	}
	u := url.URL{Scheme: "snell", Host: net.JoinHostPort(strings.Trim(strings.TrimSpace(fields[1]), "[]"), strings.TrimSpace(fields[2])), RawQuery: query.Encode(), Fragment: strings.TrimSpace(name)}
	return Parse(u.String())
}
func Export(n map[string]any) (string, error) {
	kind := text(n["type"])
	if kind == "socks5" {
		return exportSOCKS(n)
	}
	if kind == "http" {
		return exportHTTP(n)
	}
	if kind == "mieru" {
		return exportMieru(n)
	}
	if kind == "snell" {
		normalized, err := NormalizeSnell(n)
		if err != nil {
			return "", err
		}
		n = normalized
		allowed := map[string]bool{"name": true, "type": true, "server": true, "port": true, "psk": true, "version": true, "udp": true, "reuse": true, "tfo": true, "obfs-opts": true}
		for key := range n {
			if !allowed[key] {
				return "", errors.New("Snell 扩展参数请使用完整 Mihomo 订阅")
			}
		}
		if obfs, ok := n["obfs-opts"].(map[string]any); ok {
			for key := range obfs {
				if key != "mode" && key != "host" {
					return "", errors.New("Snell 高级混淆请使用完整 Mihomo 订阅")
				}
			}
		}
	}
	port := text(n["port"])
	if port == "" || text(n["server"]) == "" {
		return "", ErrURI
	}
	if n["dialer-proxy"] != nil {
		return "", errors.New("链式代理请使用完整 Mihomo 订阅")
	}
	for _, key := range []string{"plugin", "plugin-opts", "ca", "ca-str", "mptcp", "smux", "ech-opts", "packet-encoding"} {
		if n[key] != nil {
			return "", errors.New("扩展参数请使用完整 Mihomo 订阅")
		}
	}
	q := url.Values{}
	if raw, exists := n["fingerprint"]; exists {
		value, ok := raw.(string)
		if !ok || (kind != "hysteria2" && kind != "tuic") || n["tls"] == false {
			return "", ErrURI
		}
		pin, err := normalizePin(value)
		if err != nil {
			return "", err
		}
		key := "pinSHA256"
		if kind == "tuic" {
			key = "pinned_certchain_sha256"
		}
		q.Set(key, strings.ReplaceAll(pin, ":", ""))
	}
	u := url.URL{Scheme: kind, Host: net.JoinHostPort(text(n["server"]), port), Fragment: text(n["name"])}
	switch kind {
	case "vless":
		u.User = url.User(text(n["uuid"]))
		q.Set("encryption", "none")
	case "trojan", "hysteria2":
		u.User = url.User(text(n["password"]))
	case "tuic":
		u.User = url.UserPassword(text(n["uuid"]), text(n["password"]))
	case "ss":
		if strings.HasPrefix(text(n["cipher"]), "2022-") && ValidateSS2022Password(text(n["cipher"]), text(n["password"])) != nil {
			return "", ErrURI
		}
		u.User = url.User(base64.RawURLEncoding.EncodeToString([]byte(text(n["cipher"]) + ":" + text(n["password"]))))
	case "socks5", "http":
		if text(n["username"]) != "" || text(n["password"]) != "" {
			u.User = url.UserPassword(text(n["username"]), text(n["password"]))
		}
		if kind == "http" && n["tls"] == true {
			u.Scheme = "https"
		}
	case "snell":
		version := text(n["version"])
		if version == "" {
			version = "1"
		}
		q.Set("version", version)
		if obfs, ok := n["obfs-opts"].(map[string]any); ok {
			mode := text(obfs["mode"])
			if mode != "http" && mode != "tls" {
				return "", errors.New("高级 Snell 混淆请使用完整 Mihomo 订阅")
			}
			q.Set("obfs", mode)
			if text(obfs["host"]) != "" {
				q.Set("obfs-host", text(obfs["host"]))
			}
		}
		for query, key := range map[string]string{"udp": "udp", "reuse": "reuse", "tfo": "tfo"} {
			if value, ok := n[key].(bool); ok {
				q.Set(query, strconv.FormatBool(value))
			}
		}
		auth := "chacha20-ietf-poly1305:" + text(n["psk"]) + "@" + u.Host
		fragment := ""
		if u.Fragment != "" {
			fragment = "#" + url.PathEscape(u.Fragment)
		}
		return "snell://" + base64.RawStdEncoding.EncodeToString([]byte(auth)) + "?" + q.Encode() + fragment, nil
	case "vmess":
		return exportVMess(n, port)
	default:
		return "", errors.New("此协议请使用完整 Mihomo 订阅")
	}
	if n["tls"] == true && kind != "http" {
		q.Set("security", "tls")
	}
	if kind == "tuic" {
		for key, query := range map[string]string{"congestion-controller": "congestion_control", "udp-relay-mode": "udp_relay_mode"} {
			if n[key] != nil {
				q.Set(query, text(n[key]))
			}
		}
	}
	sni := text(n["sni"])
	if sni == "" {
		sni = text(n["servername"])
	}
	if sni != "" {
		q.Set("sni", sni)
	}
	if fp := text(n["client-fingerprint"]); fp != "" {
		q.Set("fp", fp)
	}
	if flow := text(n["flow"]); flow != "" {
		q.Set("flow", flow)
	}
	if raw, exists := n["reality-opts"]; exists {
		if kind != "vless" || n["tls"] != true {
			return "", ErrURI
		}
		reality, err := NormalizeReality(raw)
		if err != nil {
			return "", err
		}
		q.Set("security", "reality")
		q.Set("pbk", text(reality["public-key"]))
		if sid, exists := reality["short-id"]; exists {
			q.Set("sid", text(sid))
		}
		if flag, exists := reality["support-x25519mlkem768"]; exists {
			q.Set("support-x25519mlkem768", strconv.FormatBool(flag.(bool)))
		}
	}
	if n["skip-cert-verify"] == true {
		q.Set("insecure", "1")
	}
	if raw, exists := n["alpn"]; exists {
		list, err := ALPNValues(raw, kind == "hysteria2" || kind == "tuic")
		if err != nil {
			return "", err
		}
		values := []string{}
		for _, v := range list {
			values = append(values, v.(string))
		}
		q.Set("alpn", strings.Join(values, ","))
	}
	if n["xhttp-opts"] != nil && text(n["network"]) != "xhttp" {
		return "", ErrURI
	}
	if network := text(n["network"]); network != "" && network != "tcp" {
		q.Set("type", network)
		switch network {
		case "xhttp":
			if kind != "vless" || n["tls"] != true || n["reality-opts"] != nil || text(n["flow"]) != "" {
				return "", ErrURI
			}
			opts, err := XHTTPOptions(n["xhttp-opts"])
			if err != nil {
				return "", err
			}
			for key, value := range opts {
				q.Set(key, text(value))
			}
		case "ws", "grpc":
			path, host, err := shareTransport(n, network)
			if err != nil {
				return "", err
			}
			if network == "grpc" {
				q.Set("serviceName", path)
			} else {
				q.Set("path", path)
				q.Set("host", host)
			}
		default:
			return "", ErrURI
		}
	}
	if kind == "hysteria2" {
		u.Path = "/"
		if n["obfs"] != nil {
			q.Set("obfs", text(n["obfs"]))
			q.Set("obfs-password", text(n["obfs-password"]))
		}
		for key, query := range map[string]string{"up": "upmbps", "down": "downmbps"} {
			if n[key] != nil {
				q.Set(query, text(n[key]))
			}
		}
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}
