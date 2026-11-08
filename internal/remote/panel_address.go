package remote

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode"
)

func parsePanelAddress(input string) (*url.URL, int, error) {
	invalid := errors.New("面板地址须为完整 HTTP(S) 地址，不得包含认证信息、查询参数、控制字符或上级路径")
	input = strings.TrimSpace(input)
	if input == "" || len(input) > 2048 {
		return nil, 0, invalid
	}
	for _, r := range input {
		if unicode.IsSpace(r) || r < 32 || r == 127 || r == '\\' {
			return nil, 0, invalid
		}
	}
	u, err := url.Parse(input)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return nil, 0, invalid
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		host = ip.String()
	} else {
		host, err = certificateDomain(host)
		if err != nil {
			return nil, 0, invalid
		}
	}
	port := 80
	if u.Scheme == "https" {
		port = 443
	}
	explicit := u.Port() != ""
	if explicit {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, 0, invalid
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return nil, 0, invalid
	}
	for _, r := range u.Path {
		if r < 32 || r == 127 || r == '\\' {
			return nil, 0, invalid
		}
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, 0, invalid
		}
	}
	escaped := strings.TrimRight(u.EscapedPath(), "/") + "/"
	u.Path, err = url.PathUnescape(escaped)
	if err != nil {
		return nil, 0, invalid
	}
	u.RawPath = escaped
	u.Host = host
	if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	}
	if explicit {
		u.Host = net.JoinHostPort(host, strconv.Itoa(port))
	}
	return u, port, nil
}
