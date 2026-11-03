package remote

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

type PanelSession struct {
	mu                   sync.Mutex
	Jar                  http.CookieJar
	CSRF                 string
	LoggedIn, LegacyCSRF bool
	APIPrefix, WebPrefix string
	BlockedUntil         time.Time
}

func NewPanelSession() *PanelSession {
	jar, _ := cookiejar.New(nil)
	return &PanelSession{Jar: jar, APIPrefix: "panel/api", WebPrefix: "panel"}
}

type Panel struct {
	base                            *url.URL
	client                          *http.Client
	state                           *PanelSession
	username, password, token, kind string
	existing                        bool
	run                             func(context.Context, string, int) (string, error)
}
type panelStatus struct{ Code int }

func (e panelStatus) Error() string { return "面板接口 HTTP " + strconv.Itoa(e.Code) }

// NewPinnedPanel only dials remote loopback through an already authenticated,
// host-key-pinned SSH connection. The URL controls Host, TLS SNI and base path,
// never the TCP destination. Redirects are rejected.
func NewPinnedPanel(connection *ssh.Client, record Record, password, token string, state *PanelSession) (*Panel, error) {
	address := value(record["panelAddress"])
	if address == "" {
		address = value(record["panelUrl"])
	}
	u, err := url.Parse(address)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("请先配置面板完整地址，包含端口和访问路径")
	}
	port := 443
	if u.Scheme == "http" {
		port = 80
	}
	if u.Port() != "" {
		port, err = strconv.Atoi(u.Port())
		if err != nil || port < 1 || port > 65535 {
			return nil, errors.New("面板端口无效")
		}
	}
	u.Host = net.JoinHostPort(u.Hostname(), strconv.Itoa(port))
	transport := &http.Transport{Proxy: nil, ResponseHeaderTimeout: 20 * time.Second, TLSHandshakeTimeout: 10 * time.Second, DisableKeepAlives: true,
		// The pinned SSH channel authenticates this private loopback TLS hop; no
		// unverified TLS connection is ever made directly to the supplied URL.
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true, ServerName: u.Hostname(), MinVersion: tls.VersionTLS12},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != u.Host {
				return nil, errors.New("面板请求目标发生变化")
			}
			return connection.DialContext(ctx, "tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		},
	}
	return newPanel(u, transport, record, password, token, state), nil
}
func newPanel(base *url.URL, transport http.RoundTripper, record Record, password, token string, state *PanelSession) *Panel {
	if state == nil {
		state = NewPanelSession()
	}
	client := &http.Client{Transport: transport, Jar: state.Jar, Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	return &Panel{base: base, client: client, state: state, username: value(record["panelUser"]), password: password, token: token, kind: value(record["installType"]), existing: record["connectionMode"] == "existing"}
}
func (p *Panel) raw(ctx context.Context, path string, payload Record, method string, bearer bool, jsonBody ...bool) (any, error) {
	if method == "" {
		method = "GET"
		if payload != nil {
			method = "POST"
		}
	}
	route := strings.TrimLeft(path, "/")
	if strings.HasPrefix(route, "panel/api/") {
		route = p.state.APIPrefix + strings.TrimPrefix(route, "panel/api")
	} else if strings.HasPrefix(route, "panel/xray/") {
		route = p.state.WebPrefix + strings.TrimPrefix(route, "panel")
	}
	endpoint := *p.base
	endpoint.RawPath = strings.TrimRight(p.base.EscapedPath(), "/") + "/" + route
	decodedPath, pathErr := url.PathUnescape(endpoint.RawPath)
	if pathErr != nil {
		return nil, errors.New("面板接口路径无效")
	}
	endpoint.Path = decodedPath
	var body io.Reader
	isJSON := len(jsonBody) > 0 && jsonBody[0]
	if payload != nil && isJSON {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.New("面板 JSON 参数无法编码")
		}
		body = strings.NewReader(string(raw))
	} else if payload != nil {
		form := url.Values{}
		for key, v := range payload {
			switch item := v.(type) {
			case string:
				form.Set(key, item)
			case bool:
				form.Set(key, strconv.FormatBool(item))
			case json.Number:
				form.Set(key, string(item))
			case int:
				form.Set(key, strconv.Itoa(item))
			case int64:
				form.Set(key, strconv.FormatInt(item, 10))
			default:
				raw, err := json.Marshal(v)
				if err != nil {
					return nil, errors.New("面板参数无法编码")
				}
				form.Set(key, string(raw))
			}
		}
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, errors.New("面板请求无效")
	}
	req.Header.Set("X-Requested-With", "XMLHttpRequest")
	if payload != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if isJSON {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if bearer && p.token != "" {
		req.Header.Set("Authorization", "Bearer "+p.token)
	} else if p.state.CSRF != "" {
		req.Header.Set("X-CSRF-Token", p.state.CSRF)
	}
	response, err := p.client.Do(req)
	if err != nil {
		return nil, errors.New("面板请求连接中断或超时；修改结果未确认，请刷新核对，勿重复提交")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 4<<20+1))
	if err != nil {
		return nil, errors.New("面板响应读取失败")
	}
	if len(raw) > 4<<20 {
		return nil, errors.New("面板响应超过 4 MB 限制")
	}
	if response.StatusCode != http.StatusOK {
		return nil, panelStatus{Code: response.StatusCode}
	}
	var result struct {
		Success bool `json:"success"`
		Obj     any  `json:"obj"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		return nil, errors.New("面板返回非 JSON 内容，请核对版本与路径")
	}
	if !result.Success {
		return nil, errors.New("面板拒绝了请求，请核对凭据、版本及接口参数")
	}
	return result.Obj, nil
}
func (p *Panel) csrf(ctx context.Context) error {
	if p.state.CSRF != "" || p.state.LegacyCSRF {
		return nil
	}
	value, err := p.raw(ctx, "csrf-token", nil, "GET", false)
	var status panelStatus
	if errors.As(err, &status) && status.Code == 404 && p.existing {
		p.state.LegacyCSRF = true
		return nil
	}
	if err != nil {
		return err
	}
	token, ok := value.(string)
	if !ok || token == "" || len(token) > 256 {
		return errors.New("面板未返回有效 CSRF 令牌")
	}
	p.state.CSRF = token
	return nil
}
func (p *Panel) login(ctx context.Context) error {
	if p.state.LoggedIn {
		return nil
	}
	if time.Now().Before(p.state.BlockedUntil) {
		return errors.New("面板登录失败后暂停重试 60 秒，请检查凭据和双因素验证")
	}
	if err := p.csrf(ctx); err != nil {
		return err
	}
	if _, err := p.raw(ctx, "login", Record{"username": p.username, "password": p.password}, "POST", false); err != nil {
		p.state.LoggedIn = false
		p.state.BlockedUntil = time.Now().Add(time.Minute)
		return errors.New("面板登录失败，请核对账号、密码和双因素验证")
	}
	p.state.LoggedIn = true
	p.state.BlockedUntil = time.Time{}
	return nil
}
func (p *Panel) request(ctx context.Context, path string, payload Record, method string, retry bool, jsonBody ...bool) (any, error) {
	cookie := p.token == "" || strings.HasPrefix(path, "panel/xray/") || p.state.APIPrefix != "panel/api"
	if path == "login" {
		return nil, p.login(ctx)
	}
	if path == "csrf-token" {
		return nil, p.csrf(ctx)
	}
	if cookie {
		if err := p.login(ctx); err != nil {
			return nil, err
		}
		if payload != nil {
			if err := p.csrf(ctx); err != nil {
				return nil, err
			}
		}
	}
	result, err := p.raw(ctx, path, payload, method, !cookie, jsonBody...)
	var status panelStatus
	if errors.As(err, &status) {
		if status.Code == 404 && path == "panel/api/inbounds/list" && p.kind == "x-ui" && p.state.APIPrefix == "panel/api" {
			p.state.APIPrefix = "xui/API"
			p.state.WebPrefix = "xui"
			return p.request(ctx, path, payload, method, retry, jsonBody...)
		}
		if status.Code == 401 && cookie && retry {
			p.state.LoggedIn = false
			p.state.CSRF = ""
			p.state.LegacyCSRF = false
			jar, _ := cookiejar.New(nil)
			p.state.Jar = jar
			p.client.Jar = jar
			return p.request(ctx, path, payload, method, false, jsonBody...)
		}
		return nil, fmt.Errorf("%w，请核对面板状态、端口、路径和 API 权限", status)
	}
	return result, err
}

// Request serializes session/CSRF transitions. Only an explicit unauthenticated
// response is retried; interrupted mutations are never replayed automatically.
func (p *Panel) Request(ctx context.Context, path string, payload Record, method string) (any, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return p.request(ctx, path, payload, method, true)
}

// Mutations do not replay even an explicit unauthenticated response. Refreshing
// the list can recover authentication before another explicit user action.
func (p *Panel) RequestOnce(ctx context.Context, path string, payload Record) (any, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return p.request(ctx, path, payload, "POST", false)
}

func (p *Panel) RequestJSON(ctx context.Context, path string, payload Record) (any, error) {
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	return p.request(ctx, path, payload, "POST", true, true)
}
