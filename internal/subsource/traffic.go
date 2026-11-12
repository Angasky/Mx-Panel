package subsource

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

type Traffic struct {
	Upload   uint64 `json:"upload"`
	Download uint64 `json:"download"`
	Total    uint64 `json:"total"`
	Expire   int64  `json:"expire"`
}

// A missing field is unknown, never a zero-usage subscription.
func ParseTraffic(raw string) (Traffic, error) {
	var t Traffic
	if len(raw) > 4096 {
		return t, errors.New("流量响应头过长")
	}
	values := map[string]string{}
	for _, part := range strings.Split(raw, ";") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if k != "upload" && k != "download" && k != "total" && k != "expire" {
			continue
		}
		if _, ok := values[k]; ok {
			return t, errors.New("流量响应头存在重复字段")
		}
		values[k] = v
	}
	for _, k := range []string{"upload", "download", "total"} {
		v, ok := values[k]
		if !ok {
			return t, errors.New("订阅未提供完整的 Subscription-Userinfo 流量信息")
		}
		n, e := strconv.ParseUint(v, 10, 64)
		if e != nil || n > 9007199254740991 {
			return t, errors.New("流量响应头数值无效")
		}
		switch k {
		case "upload":
			t.Upload = n
		case "download":
			t.Download = n
		case "total":
			t.Total = n
		}
	}
	if t.Upload > 9007199254740991-t.Download {
		return t, errors.New("累计流量超出精确显示范围")
	}
	if v, ok := values["expire"]; ok {
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n < 0 || n > 7258118400 {
			return t, errors.New("到期时间无效")
		}
		t.Expire = n
	}
	return t, nil
}
func (c *Client) FetchTraffic(ctx context.Context, raw string) (Traffic, error) {
	var t Traffic
	if len(raw) > 8192 {
		return t, errors.New("订阅地址过长")
	}
	u, e := url.Parse(strings.TrimSpace(raw))
	if e != nil {
		return t, errors.New("订阅地址格式无效")
	}
	if e = validURL(u); e != nil {
		return t, e
	}
	u.Fragment = ""
	req, e := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if e != nil {
		return t, errors.New("请求创建失败")
	}
	req.Header.Set("User-Agent", "clash.meta")
	client := *c.http
	redirect := client.CheckRedirect
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != "https" {
			return errors.New("流量查询不允许降级 HTTP")
		}
		if redirect != nil {
			return redirect(req, via)
		}
		if len(via) >= 5 {
			return errors.New("跳转次数过多")
		}
		return validURL(req.URL)
	}
	resp, e := client.Do(req)
	if e != nil {
		return t, errors.New("流量读取失败，请检查公网地址、证书和连接")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return t, errors.New("订阅服务器未返回成功状态")
	}
	// No node body is read or stored. Reuse DNS pinning and redirect validation.
	if len(resp.Header.Values("Subscription-Userinfo")) != 1 {
		return t, errors.New("订阅未提供唯一的 Subscription-Userinfo 响应头")
	}
	return ParseTraffic(resp.Header.Get("Subscription-Userinfo"))
}
