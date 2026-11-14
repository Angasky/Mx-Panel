// Package ai implements user-supplied AI endpoints without granting tools or shell access.
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
)

type Config struct {
	Protocol     string `json:"protocol"`
	BaseURL      string `json:"baseUrl"`
	Model        string `json:"model"`
	MaxTokens    int    `json:"maxTokens"`
	LegacyTokens bool   `json:"legacyTokens"`
}
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type Reply struct {
	Text         string `json:"text"`
	InputTokens  int    `json:"inputTokens"`
	OutputTokens int    `json:"outputTokens"`
	Truncated    bool   `json:"truncated"`
}

var modelName = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}$`)

func Normalize(c Config) (Config, error) {
	defaults := map[string]string{"openai-chat": "https://api.openai.com/v1", "openai-responses": "https://api.openai.com/v1", "anthropic": "https://api.anthropic.com/v1", "gemini": "https://generativelanguage.googleapis.com/v1beta"}
	base, ok := defaults[c.Protocol]
	if !ok {
		return c, errors.New("请选择支持的 AI 接口格式")
	}
	c.BaseURL = strings.TrimRight(strings.TrimSpace(c.BaseURL), "/")
	if c.BaseURL == "" {
		c.BaseURL = base
	}
	suffix := map[string]string{"openai-chat": "/chat/completions", "openai-responses": "/responses", "anthropic": "/messages"}[c.Protocol]
	if suffix != "" {
		c.BaseURL = strings.TrimSuffix(c.BaseURL, suffix)
	}
	u, e := url.Parse(c.BaseURL)
	if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || len(c.BaseURL) > 2048 || strings.ContainsAny(u.Hostname(), "%\\\x00\r\n") {
		return c, errors.New("API 地址须为完整 HTTPS 基础地址，不能包含密钥、账号或查询参数")
	}
	if strings.HasSuffix(u.Host, ":") {
		return c, errors.New("AI API 端口无效")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return c, errors.New("AI API 端口应为 1–65535")
		}
	}
	if ip, e := netip.ParseAddr(u.Hostname()); e == nil && !netguard.PublicAddress(ip) {
		return c, errors.New("AI API 地址必须是公网地址")
	}
	c.Model = strings.TrimSpace(c.Model)
	if c.Protocol == "gemini" {
		c.Model = strings.TrimPrefix(c.Model, "models/")
	}
	if !modelName.MatchString(c.Model) || (c.Protocol == "gemini" && strings.ContainsAny(c.Model, "/:")) {
		return c, errors.New("请填写有效模型 ID")
	}
	if c.MaxTokens == 0 {
		c.MaxTokens = 2048
	}
	if c.MaxTokens < 128 || c.MaxTokens > 8192 {
		return c, errors.New("最大输出长度应为 128–8192 tokens")
	}
	return c, nil
}
func ValidKey(key string) bool {
	return len(key) >= 8 && len(key) <= 4096 && !strings.ContainsAny(key, "\r\n\x00\t ")
}
func publicDial(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return nil, errors.New("AI API 地址无效")
	}
	ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if e != nil || len(ips) == 0 {
		return nil, errors.New("AI API 域名解析失败")
	}
	for _, ip := range ips {
		if !netguard.PublicAddress(ip) {
			return nil, errors.New("AI API 域名必须仅解析到公网地址")
		}
	}
	d := net.Dialer{Timeout: 8 * time.Second}
	for _, ip := range ips {
		c, e := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if e == nil {
			return c, nil
		}
		if ctx.Err() != nil {
			break
		}
	}
	return nil, errors.New("AI API 连接失败")
}
func NewHTTPClient() *http.Client {
	return &http.Client{Timeout: 55 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("AI API 不允许重定向，请填写最终地址")
	}, Transport: &http.Transport{Proxy: nil, DialContext: publicDial, TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 55 * time.Second, MaxResponseHeaderBytes: 64 << 10, MaxIdleConns: 16, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second}}
}

func BuildRequest(ctx context.Context, c Config, key, system string, messages []Message) (*http.Request, error) {
	var e error
	c, e = Normalize(c)
	if e != nil {
		return nil, e
	}
	if !ValidKey(key) {
		return nil, errors.New("API Key 格式无效")
	}
	if len(messages) < 1 || len(messages) > 40 {
		return nil, errors.New("对话长度超过限制，请新建对话")
	}
	size := len(system)
	for _, m := range messages {
		if (m.Role != "user" && m.Role != "assistant") || strings.TrimSpace(m.Content) == "" {
			return nil, errors.New("对话消息无效")
		}
		size += len(m.Content)
	}
	if size > 180000 {
		return nil, errors.New("对话内容过长，请新建对话")
	}
	endpoint := c.BaseURL
	body := map[string]any{"model": c.Model}
	switch c.Protocol {
	case "openai-chat":
		endpoint += "/chat/completions"
		body["messages"] = append([]Message{{"system", system}}, messages...)
		body["stream"] = false
		if c.LegacyTokens {
			body["max_tokens"] = c.MaxTokens
		} else {
			body["max_completion_tokens"] = c.MaxTokens
		}
	case "openai-responses":
		endpoint += "/responses"
		body["input"] = messages
		body["instructions"] = system
		body["max_output_tokens"] = c.MaxTokens
		body["store"] = false
		body["stream"] = false
	case "anthropic":
		endpoint += "/messages"
		body["messages"] = messages
		body["system"] = system
		body["max_tokens"] = c.MaxTokens
		body["stream"] = false
	case "gemini":
		endpoint += "/models/" + url.PathEscape(c.Model) + ":generateContent"
		contents := []any{}
		for _, m := range messages {
			role := m.Role
			if role == "assistant" {
				role = "model"
			}
			contents = append(contents, map[string]any{"role": role, "parts": []any{map[string]string{"text": m.Content}}})
		}
		body = map[string]any{"contents": contents, "systemInstruction": map[string]any{"parts": []any{map[string]string{"text": system}}}, "generationConfig": map[string]any{"maxOutputTokens": c.MaxTokens}}
	}
	raw, e := json.Marshal(body)
	if e != nil {
		return nil, e
	}
	r, e := http.NewRequestWithContext(ctx, "POST", endpoint, bytes.NewReader(raw))
	if e != nil {
		return nil, errors.New("AI 请求创建失败")
	}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Accept", "application/json")
	switch c.Protocol {
	case "anthropic":
		r.Header.Set("x-api-key", key)
		r.Header.Set("anthropic-version", "2023-06-01")
	case "gemini":
		r.Header.Set("x-goog-api-key", key)
	default:
		r.Header.Set("Authorization", "Bearer "+key)
	}
	return r, nil
}
func Complete(ctx context.Context, client *http.Client, c Config, key, system string, messages []Message) (Reply, error) {
	req, e := BuildRequest(ctx, c, key, system, messages)
	if e != nil {
		return Reply{}, e
	}
	response, e := client.Do(req)
	if e != nil {
		if ctx.Err() != nil {
			return Reply{}, errors.New("AI 请求已取消或超时")
		}
		return Reply{}, errors.New("无法连接 AI API，请检查地址、DNS、HTTPS 证书和网络")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		hint := "上游服务返回错误"
		switch response.StatusCode {
		case 401, 403:
			hint = "API Key 无效、权限不足或账号受限"
		case 404:
			hint = "接口路径或模型不存在"
		case 429:
			hint = "额度不足或请求过于频繁"
		case 400, 422:
			hint = "模型不支持当前请求参数，请检查接口格式和输出长度设置"
		}
		return Reply{}, fmt.Errorf("%s（HTTP %d）", hint, response.StatusCode)
	}
	raw, e := io.ReadAll(io.LimitReader(response.Body, 2<<20+1))
	if e != nil || len(raw) > 2<<20 {
		return Reply{}, errors.New("AI 响应读取失败或超过 2 MB")
	}
	reply, e := ParseReply(c.Protocol, raw)
	if e != nil {
		return Reply{}, e
	}
	reply.Text = strings.ReplaceAll(reply.Text, key, "[API Key 已隐藏]")
	return reply, nil
}
func ParseReply(protocol string, raw []byte) (Reply, error) {
	var doc struct {
		Choices []struct {
			Message struct {
				Content json.RawMessage
				Refusal string
			}
			FinishReason string `json:"finish_reason"`
		}
		Output []struct {
			Type    string
			Content []struct{ Type, Text, Refusal string }
		}
		Content    []struct{ Type, Text string }
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text    string
					Thought bool
				}
			}
			FinishReason string
		}
		Usage struct {
			Prompt     int `json:"prompt_tokens"`
			Completion int `json:"completion_tokens"`
			Input      int `json:"input_tokens"`
			Output     int `json:"output_tokens"`
		}
		UsageMetadata struct {
			Prompt int `json:"promptTokenCount"`
			Output int `json:"candidatesTokenCount"`
		}
		Status     string
		StopReason string `json:"stop_reason"`
	}
	if json.Unmarshal(raw, &doc) != nil {
		return Reply{}, errors.New("AI API 返回了无效 JSON，请核对接口格式")
	}
	var reply Reply
	var parts []string
	switch protocol {
	case "openai-chat":
		if len(doc.Choices) > 0 {
			c := doc.Choices[0]
			var text string
			if json.Unmarshal(c.Message.Content, &text) == nil {
				parts = append(parts, text)
			} else {
				var rows []struct{ Type, Text string }
				if json.Unmarshal(c.Message.Content, &rows) == nil {
					for _, r := range rows {
						if r.Type == "text" {
							parts = append(parts, r.Text)
						}
					}
				}
			}
			if c.Message.Refusal != "" {
				parts = append(parts, c.Message.Refusal)
			}
			reply.Truncated = c.FinishReason == "length"
		}
		reply.InputTokens = doc.Usage.Prompt
		reply.OutputTokens = doc.Usage.Completion
	case "openai-responses":
		for _, o := range doc.Output {
			if o.Type == "message" {
				for _, p := range o.Content {
					if p.Type == "output_text" {
						parts = append(parts, p.Text)
					} else if p.Type == "refusal" {
						parts = append(parts, p.Refusal)
					}
				}
			}
		}
		reply.InputTokens = doc.Usage.Input
		reply.OutputTokens = doc.Usage.Output
		reply.Truncated = doc.Status == "incomplete"
	case "anthropic":
		for _, p := range doc.Content {
			if p.Type == "text" {
				parts = append(parts, p.Text)
			}
		}
		reply.InputTokens = doc.Usage.Input
		reply.OutputTokens = doc.Usage.Output
		reply.Truncated = doc.StopReason == "max_tokens"
	case "gemini":
		if len(doc.Candidates) > 0 {
			for _, p := range doc.Candidates[0].Content.Parts {
				if !p.Thought {
					parts = append(parts, p.Text)
				}
			}
			reply.Truncated = doc.Candidates[0].FinishReason == "MAX_TOKENS"
		}
		reply.InputTokens = doc.UsageMetadata.Prompt
		reply.OutputTokens = doc.UsageMetadata.Output
	default:
		return Reply{}, errors.New("AI 接口格式无效")
	}
	reply.Text = strings.TrimSpace(strings.Join(parts, "\n"))
	if reply.Text == "" {
		return Reply{}, errors.New("模型没有返回文本，可能被内容策略拦截或输出预算已耗尽")
	}
	if len(reply.Text) > 64000 {
		return Reply{}, errors.New("AI 回复超过长度限制，请降低最大输出长度")
	}
	return reply, nil
}
