package web

import (
	"errors"
	"regexp"
	"strings"
)

var quantumultXProduct = regexp.MustCompile(`(?i)\bquantumult(?:%20|[ ]+)x\b`)

var subscriptionProduct = regexp.MustCompile(`[a-z0-9]+(?:[-_][a-z0-9]+)*`)

// Product tokens only; do not guess from OS/browser strings or fallback to a
// potentially incompatible format. Multiple products must agree on the format.
func autoSubscriptionFormat(agent string) (string, error) {
	if len(agent) > 1024 {
		return "", errors.New("客户端标识过长，请使用专用格式链接")
	}
	products := map[string]string{
		"clash": "clash", "clash-meta": "clash", "clash-verge": "clash", "clash-verge-rev": "clash", "mihomo": "clash",
		"shadowrocket": "shadowrocket", "v2rayn": "v2rayn", "v2rayng": "v2rayng",
		"sing-box": "sing-box", "singbox": "sing-box", "surge": "surge", "loon": "loon",
		"quantumult-x": "quantumult-x", "quantumultx": "quantumult-x",
		"stash": "stash", "surfboard": "surfboard", "egern": "egern",
	}
	agent = quantumultXProduct.ReplaceAllString(agent, "quantumult-x")
	found := ""
	for _, token := range subscriptionProduct.FindAllString(strings.ToLower(agent), -1) {
		format := products[token]
		if format == "" {
			continue
		}
		if found != "" && found != format {
			return "", errors.New("客户端标识包含冲突格式，请使用对应客户端的专用链接")
		}
		found = format
	}
	if found == "" {
		return "", errors.New("无法识别客户端，请从面板复制对应客户端的专用订阅链接")
	}
	return found, nil
}
