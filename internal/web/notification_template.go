package web

import (
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

func validateNotificationTemplate(value string) error {
	if value == "" {
		return nil
	}
	if !utf8.ValidString(value) || utf8.RuneCountInString(value) > 512 || strings.ContainsFunc(value, func(r rune) bool { return unicode.IsControl(r) && r != '\n' && r != '\t' }) {
		return errors.New("通知模板最多 512 个字符，只允许换行和制表控制字符")
	}
	if strings.Count(value, "{message}") != 1 || strings.Count(value, "{time}") > 1 {
		return errors.New("模板必须包含一次 {message}，可选一次 {time}")
	}
	rest := strings.ReplaceAll(strings.ReplaceAll(value, "{message}", ""), "{time}", "")
	if strings.ContainsAny(rest, "{}") {
		return errors.New("模板仅支持 {message} 和 {time}，不支持其他花括号或变量")
	}
	return nil
}
func notificationUnits(value string) int {
	n := 0
	for _, r := range value {
		n++
		if r > 0xffff {
			n++
		}
	}
	return n
}
func notificationPrefix(value string, limit int) string {
	n := 0
	for i, r := range value {
		size := 1
		if r > 0xffff {
			size = 2
		}
		if n+size > limit {
			return value[:i]
		}
		n += size
	}
	return value
}

// Never evaluate templates recursively: braces in an event remain plain text.
// Use UTF-16 units as a conservative Telegram text budget, including emoji.
func renderNotificationText(template, message string, eventTime int64) (string, bool) {
	if template == "" {
		template = "{message}"
	}
	template = strings.ReplaceAll(template, "{time}", time.Unix(eventTime, 0).UTC().Format("2006-01-02 15:04:05 UTC"))
	before, after, _ := strings.Cut(template, "{message}")
	limit := 4000 - notificationUnits(before) - notificationUnits(after)
	truncated := notificationUnits(message) > limit
	if truncated {
		suffix := "\n[内容过长已截断，请查看面板]"
		message = notificationPrefix(message, limit-notificationUnits(suffix)) + suffix
	}
	return before + message + after, truncated
}
func (s *Server) notificationTemplateRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/notifications/template-preview" {
		return false
	}
	if r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	var input struct {
		Template string `json:"template"`
		Sample   string `json:"sample"`
	}
	if readJSON(w, r, &input) != nil {
		return true
	}
	if err := validateNotificationTemplate(input.Template); err != nil {
		problem(w, 400, err.Error())
		return true
	}
	samples := map[string]string{
		"monitor":  "服务器「示例香港」连续监控采样失败，请检查连接；不代表代理服务一定离线。",
		"traffic":  "订阅「示例套餐」已使用 92% 流量（示例数据）。",
		"expiry":   "服务器「示例服务器」将在 7 天后到期，请核对续费（示例数据）。",
		"recovery": "监控采样恢复：服务器「示例香港」（示例数据）。",
		"daily":    "网卡观测流量日报（示例数据）\n示例服务器：上传 2 GiB，下载 8 GiB。\n观测流量不等同于订阅账单。",
	}
	message, ok := samples[input.Sample]
	if !ok {
		problem(w, 400, "请选择有效的通知预览类型")
		return true
	}
	rendered, truncated := renderNotificationText(input.Template, message, s.now().Unix())
	respond(w, 200, map[string]any{"text": rendered, "truncated": truncated, "sample": true})
	return true
}
