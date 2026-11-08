package subscriptions

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
)

type Format struct {
	ID, Name, Note string
	Snell, TUIC    bool
}

var formats = []Format{
	{"v2rayn-ha", "电脑 v2rayN · Xray 主备配置", "每个主备组一份完整 JSON，固定优先顺序。", false, false},
	{"v2rayng-ha", "安卓 v2rayNG · Xray 主备配置", "本地 SOCKS / HTTP 端口为 10808 / 10809。", false, false},
	{"shadowrocket-ha", "小火箭主备 · 第一步：节点订阅", "先导入节点，再启用配套策略配置。", true, true},
	{"shadowrocket-config", "小火箭主备 · 第二步：策略配置", "按入口优先顺序 fallback，勿开启全局回退。", true, true},
	{"v2rayn", "电脑 v2rayN 节点订阅", "流量与到期信息使用独立信息节点展示。", false, true},
	{"v2rayng", "安卓 v2rayNG 节点订阅", "过滤 TUIC 与 Snell；流量与到期信息随订阅更新。", false, false},
	{"v2ray", "V2Ray 通用节点订阅", "兼容旧链接；协议支持取决于客户端内核。", false, true},
	{"shadowrocket", "Shadowrocket（小火箭）订阅", "包含 Snell PSK，流量与到期信息使用独立信息节点展示。", true, true},
}

type Export struct {
	Body    []byte
	Skipped []Record
	Count   int
}

func formatByID(id string) (Format, error) {
	for _, f := range formats {
		if f.ID == id {
			return f, nil
		}
	}
	return Format{}, errors.New("转换格式尚未适配")
}
func usageNodes(info Record, now time.Time) []Record {
	if info["configured"] != true {
		return nil
	}
	gib := func(v any) string { n, _ := number(v, 0); return fmt.Sprintf("%.2f GB", float64(n)/(1024*1024*1024)) }
	total, remaining := "不限量", "不限量"
	if info["total"] != nil {
		total = gib(info["total"])
	}
	if info["remaining"] != nil {
		remaining = gib(info["remaining"])
	}
	duration := "长期有效"
	if info["expire"] != nil {
		expire, _ := number(info["expire"], 0)
		if expire <= now.Unix() {
			duration = "已到期"
		} else {
			duration = fmt.Sprintf("剩余 %d 天", (expire-now.Unix()+86399)/86400)
		}
		duration += " · 到期 " + time.Unix(expire, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	labels := []string{"订阅信息 · 已用 " + gib(info["used"]) + " / 总量 " + total, "订阅信息 · 剩余流量 " + remaining, "订阅信息 · " + duration}
	out := []Record{}
	for _, name := range labels {
		out = append(out, Record{"name": name, "type": "vmess", "server": "127.0.0.1", "port": 9, "uuid": "00000000-0000-4000-8000-000000000000", "alterId": 0, "cipher": "auto", "network": "tcp"})
	}
	return out
}

// usageLabel mirrors client_adapter.usage_label for configuration exports.
func usageLabel(info Record) string {
	if info["configured"] != true {
		return ""
	}
	size := func(value any) string {
		n, _ := number(value, 0)
		amount := float64(n)
		for _, unit := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
			if amount < 1024 || unit == "TiB" {
				return fmt.Sprintf("%.2f %s", amount, unit)
			}
			amount /= 1024
		}
		return ""
	}
	remaining, expiry := "不限量", "长期有效"
	if info["remaining"] != nil {
		remaining = size(info["remaining"])
	}
	if info["expire"] != nil {
		expire, _ := number(info["expire"], 0)
		expiry = time.Unix(expire, 0).UTC().Format("2006-01-02 15:04 UTC")
	}
	return "已用 " + size(info["used"]) + " · 剩余 " + remaining + " · 到期 " + expiry
}

func Convert(source config.Subscription, format string, now time.Time) (Export, error) {
	if format == "v2rayn-ha" || format == "v2rayng-ha" {
		return convertXrayHA(source)
	}
	if format == "shadowrocket-ha" || format == "shadowrocket-config" {
		return convertRocketHA(source, format == "shadowrocket-config")
	}
	f, err := formatByID(format)
	if err != nil {
		return Export{}, err
	}
	result := Export{Skipped: []Record{}}
	uris := []string{}
	for _, node := range objects(source.Document["proxies"]) {
		reason := ""
		kind := text(node["type"])
		if text(node["dialer-proxy"]) != "" {
			reason = "链式代理需要完整 Mihomo 订阅"
		} else if format == "shadowrocket" && node["network"] == "xhttp" {
			reason = "此 XHTTP 节点请使用 Mihomo 或 Xray 客户端订阅"
		} else if kind == "snell" && !f.Snell || kind == "tuic" && !f.TUIC || kind == "mieru" {
			reason = "客户端或该导出格式不支持此协议"
		}
		uri := ""
		if reason == "" {
			uri, err = links.Export(node)
			if err != nil {
				reason = "节点参数未适配，请使用完整 Mihomo 订阅"
			}
		}
		if reason != "" {
			result.Skipped = append(result.Skipped, Record{"name": node["name"], "type": kind, "reason": reason})
			continue
		}
		uris = append(uris, uri)
	}
	result.Count = len(uris)
	if result.Count == 0 {
		return result, errors.New("没有可转换的兼容节点")
	}
	info := []string{}
	for _, node := range usageNodes(source.Traffic, now) {
		uri, e := links.Export(node)
		if e != nil {
			return result, e
		}
		info = append(info, uri)
	}
	result.Body = []byte(base64.StdEncoding.EncodeToString([]byte(strings.Join(append(info, uris...), "\n"))))
	return result, nil
}
func ConversionReport(source config.Subscription, now time.Time) []Record {
	reports := []Record{}
	for _, format := range formats {
		result, err := Convert(source, format.ID, now)
		message := ""
		if err != nil {
			message = err.Error()
		}
		unit := "节点"
		if format.ID == "shadowrocket-config" || format.ID == "v2rayn-ha" || format.ID == "v2rayng-ha" {
			unit = "主备组"
		}
		reports = append(reports, Record{"id": format.ID, "name": format.Name, "note": format.Note, "supported": result.Count, "unit": unit, "available": err == nil, "error": message, "skipped": result.Skipped, "url": "/convert/" + url.PathEscape(source.Slug) + "/" + format.ID})
	}
	return reports
}
