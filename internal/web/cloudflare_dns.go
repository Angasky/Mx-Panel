package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

type cfDNSRecord struct {
	ID      string `json:"id"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Proxied bool   `json:"proxied"`
}
type cfDNSClient struct {
	client           *http.Client
	base, key, email string
}

func (c cfDNSClient) call(ctx context.Context, method, path string, body any, out any) error {
	var b bytes.Buffer
	if body != nil {
		if e := json.NewEncoder(&b).Encode(body); e != nil {
			return e
		}
	}
	req, e := http.NewRequestWithContext(ctx, method, c.base+path, &b)
	if e != nil {
		return errors.New("Cloudflare 请求无效")
	}
	if c.email != "" {
		req.Header.Set("X-Auth-Email", c.email)
		req.Header.Set("X-Auth-Key", c.key)
	} else {
		req.Header.Set("Authorization", "Bearer "+c.key)
	}
	req.Header.Set("Content-Type", "application/json")
	res, e := c.client.Do(req)
	if e != nil {
		return errors.New("Cloudflare 连接失败或超时")
	}
	defer res.Body.Close()
	var envelope struct {
		Success    bool            `json:"success"`
		Result     json.RawMessage `json:"result"`
		ResultInfo struct {
			TotalCount int `json:"total_count"`
		} `json:"result_info"`
	}
	if json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(&envelope) != nil || res.StatusCode < 200 || res.StatusCode >= 300 || !envelope.Success {
		return errors.New("Cloudflare 请求失败，请核对凭据、Zone Read / DNS Edit 权限与请求频率")
	}
	if strings.Contains(path, "/dns_records") && envelope.ResultInfo.TotalCount > 100 {
		return errors.New("同名 DNS 记录过多，停止自动处理")
	}
	if out != nil && json.Unmarshal(envelope.Result, out) != nil {
		return errors.New("Cloudflare 响应格式无效")
	}
	return nil
}

var cfID = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)

func cfDomain(s string) string {
	s = strings.TrimSpace(s)
	var err error
	s, err = idna.Lookup.ToASCII(s)
	if err != nil {
		return ""
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	if len(s) > 253 || !strings.Contains(s, ".") || net.ParseIP(s) != nil {
		return ""
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 || !regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`).MatchString(label) {
			return ""
		}
	}
	return s
}
func (c cfDNSClient) bind(ctx context.Context, zone, domain, address string) (bool, error) {
	var zones []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if e := c.call(ctx, "GET", "/zones?name="+url.QueryEscape(zone)+"&per_page=100", nil, &zones); e != nil {
		return false, e
	}
	if len(zones) != 1 || cfDomain(zones[0].Name) != zone || !cfID.MatchString(zones[0].ID) {
		return false, errors.New("未找到唯一的 Cloudflare 域名区域，请填写实际 Zone 根域名")
	}
	base := "/zones/" + zones[0].ID + "/dns_records"
	var rows []cfDNSRecord
	if e := c.call(ctx, "GET", base+"?name="+url.QueryEscape(domain)+"&per_page=100", nil, &rows); e != nil {
		return false, e
	}
	kind := "AAAA"
	if net.ParseIP(address).To4() != nil {
		kind = "A"
	}
	exact := false
	for _, row := range rows {
		if cfDomain(row.Name) != domain {
			return false, errors.New("Cloudflare 返回了非目标域名的记录")
		}
		if row.Type == "CNAME" || (row.Type == "A" || row.Type == "AAAA") && (row.Type != kind || !net.ParseIP(row.Content).Equal(net.ParseIP(address)) || row.Proxied) {
			return false, errors.New("域名已存在其他地址、CNAME 或橙云记录，请更换子域名或在 Cloudflare 中先核对；未覆盖记录")
		}
		if row.Type == kind {
			exact = true
		}
	}
	if exact {
		return false, nil
	}
	var created cfDNSRecord
	e := c.call(ctx, "POST", base, map[string]any{"type": kind, "name": domain, "content": address, "ttl": 1, "proxied": false}, &created)
	if e != nil {
		return false, errors.New("DNS 创建未确认，请先在 Cloudflare 核对记录再重试（请求可能已被处理）")
	}
	if !cfID.MatchString(created.ID) || cfDomain(created.Name) != domain || created.Type != kind || !net.ParseIP(created.Content).Equal(net.ParseIP(address)) || created.Proxied {
		return false, errors.New("DNS 返回结果与请求不一致，请在 Cloudflare 核对，未绑定本地节点地址")
	}
	return true, nil
}
func (s *Server) cloudflareDNSRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/cloudflare-dns" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var in struct {
		UseSaved            bool    `json:"useSaved"`
		CredentialRevision  string  `json:"credentialRevision"`
		ID                  string  `json:"id"`
		Key                 string  `json:"key"`
		Email               string  `json:"email"`
		Zone                string  `json:"zone"`
		Domain              string  `json:"domain"`
		Address             string  `json:"address"`
		Confirmed           bool    `json:"confirmed"`
		ExpectedHost        *string `json:"expectedHost"`
		ExpectedNodeAddress *string `json:"expectedNodeAddress"`
	}
	if readJSON(w, r, &in) != nil {
		problem(w, 400, "参数无效")
		return true
	}
	zone, domain := cfDomain(in.Zone), cfDomain(in.Domain)
	ip := net.ParseIP(strings.TrimSpace(in.Address))
	if !in.Confirmed || zone == "" || domain == "" || (domain != zone && !strings.HasSuffix(domain, "."+zone)) || ip == nil || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() {
		problem(w, 400, "请确认操作，填写有效 Zone、所属域名及服务器公网 IPv4/IPv6")
		return true
	}
	if in.UseSaved {
		manager, err := s.remoteManager()
		if err != nil {
			problem(w, 500, "CF 设置不可用")
			return true
		}
		settings, err := manager.CloudflareSettings()
		if err != nil || settings.Secret == "" {
			problem(w, 400, "请先在设置中保存 CF 凭据")
			return true
		}
		if in.CredentialRevision != settings.Revision {
			problem(w, 409, "CF 设置已变化，请重新打开安装窗口")
			return true
		}
		in.Key, err = manager.CloudflareKey(settings)
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		in.Email = settings.Email
	}
	in.Key = strings.TrimSpace(in.Key)
	in.Email = strings.TrimSpace(in.Email)
	if len(in.Key) < 16 || len(in.Key) > 512 || strings.ContainsAny(in.Key, "\r\n\t ") {
		problem(w, 400, "CF 凭据格式无效")
		return true
	}
	if in.Email != "" {
		a, e := mail.ParseAddress(in.Email)
		if e != nil || a.Address != in.Email {
			problem(w, 400, "Global API Key 需要有效邮箱")
			return true
		}
	}
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	row, e := m.Record(in.ID)
	if e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	if (in.ExpectedHost != nil && *in.ExpectedHost != stringField(row, "host")) || (in.ExpectedNodeAddress != nil && *in.ExpectedNodeAddress != stringField(row, "nodeAddress") && domain != stringField(row, "nodeAddress")) {
		problem(w, 409, "服务器地址已变化，请刷新后重新预览；未创建 DNS")
		return true
	}
	if row["agentOnly"] == true {
		problem(w, 409, "请先启用服务器部署权限")
		return true
	}
	ctx, cancel := context.WithTimeout(r.Context(), 35*time.Second)
	defer cancel()
	client := cfDNSClient{client: &http.Client{Timeout: 12 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, base: "https://api.cloudflare.com/client/v4", key: in.Key, email: in.Email}
	created, e := client.bind(ctx, zone, domain, ip.String())
	if e != nil {
		problem(w, 409, e.Error())
		return true
	}
	if e = m.BindNodeDomain(in.ID, stringField(row, "host"), stringField(row, "nodeAddress"), domain); e != nil {
		problem(w, 409, "DNS 已存在或创建成功，但本地绑定未完成："+e.Error()+"；核对后重试，不会自动删除 DNS")
		return true
	}
	respond(w, 200, map[string]any{"ok": true, "created": created, "domain": domain, "address": ip.String(), "proxied": false})
	return true
}
