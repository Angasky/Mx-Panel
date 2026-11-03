// Package subsource reads external node subscriptions without Python processes.
package subsource

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
)

const MaxBytes = 8 << 20

type Client struct{ http *http.Client }

func NewClient() *Client {
	transport := &http.Transport{Proxy: nil, DialContext: publicDial, MaxResponseHeaderBytes: 1 << 20, MaxIdleConns: 8, MaxIdleConnsPerHost: 2, IdleConnTimeout: 30 * time.Second, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second}
	return &Client{http: &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		req.Header.Del("Referer")
		if len(via) >= 5 {
			return errors.New("订阅跳转次数过多")
		}
		return validURL(req.URL)
	}}}
}

func validURL(u *url.URL) error {
	if u == nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Opaque != "" || strings.ContainsAny(u.Hostname(), "%\\\x00\r\n") {
		return errors.New("订阅地址必须是完整的 HTTP 或 HTTPS 链接，不含账号认证段")
	}
	if u.Port() != "" {
		p, err := strconv.Atoi(u.Port())
		if err != nil || p < 1 || p > 65535 {
			return errors.New("订阅地址端口无效")
		}
	}
	return nil
}

func publicAddress(address netip.Addr) bool { return netguard.PublicAddress(address) }

// Resolve once, reject mixed public/private answers and dial the verified IP
// directly. The transport still authenticates TLS against the original hostname.
func resolvePublic(ctx context.Context, host string, lookup func(context.Context, string, string) ([]netip.Addr, error)) ([]netip.Addr, error) {
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		var err error
		addresses, err = lookup(ctx, "ip", host)
		if err != nil {
			return nil, errors.New("订阅域名解析失败")
		}
	}
	if len(addresses) == 0 {
		return nil, errors.New("订阅域名没有可用地址")
	}
	for _, ip := range addresses {
		if !publicAddress(ip) {
			return nil, errors.New("订阅地址必须解析到公网地址")
		}
	}
	return addresses, nil
}

func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	dialer := net.Dialer{Timeout: 8 * time.Second}
	return dialPublic(ctx, address, net.DefaultResolver.LookupNetIP, dialer.DialContext)
}

func dialPublic(ctx context.Context, address string, lookup func(context.Context, string, string) ([]netip.Addr, error), dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, errors.New("订阅地址无效")
	}
	addresses, err := resolvePublic(ctx, host, lookup)
	if err != nil {
		return nil, err
	}
	for _, ip := range addresses {
		connection, err := dial(ctx, "tcp", net.JoinHostPort(ip.Unmap().String(), port))
		if err == nil {
			return connection, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("订阅服务器连接失败")
}

func (c *Client) Fetch(ctx context.Context, rawURL string) (string, error) {
	if len(rawURL) > 8192 {
		return "", errors.New("订阅地址过长")
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil {
		return "", errors.New("订阅地址格式无效")
	}
	if err = validURL(u); err != nil {
		return "", err
	}
	u.Fragment = ""
	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return "", errors.New("订阅请求创建失败")
	}
	req.Header.Set("User-Agent", "Mxioc-Subscription-Importer/1.0")
	response, err := c.http.Do(req)
	// Never return url.Error: capability tokens in query strings are private.
	if err != nil {
		return "", errors.New("订阅读取失败，请检查公网地址、HTTPS 证书或连接超时")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return "", fmt.Errorf("订阅服务器返回 HTTP %d", response.StatusCode)
	}
	if response.ContentLength > MaxBytes {
		return "", errors.New("订阅内容超过 8 MB，已停止读取")
	}
	content, err := io.ReadAll(io.LimitReader(response.Body, MaxBytes+1))
	if err != nil {
		return "", errors.New("订阅内容读取失败")
	}
	if len(content) > MaxBytes {
		return "", errors.New("订阅内容超过 8 MB，已停止读取")
	}
	if !utf8.Valid(content) {
		return "", errors.New("订阅内容不是有效 UTF-8 文本")
	}
	return strings.TrimSpace(strings.TrimPrefix(string(content), "\ufeff")), nil
}
