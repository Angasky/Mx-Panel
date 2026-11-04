package remote

import (
	"errors"
	"maps"
	"slices"
)

func coreProvisionProtocol(kind, protocol string) bool {
	switch protocol {
	case "vless", "vmess", "trojan":
		return kind == "xray" || kind == "sing-box"
	case "hysteria2", "tuic":
		return kind == "sing-box"
	case "hysteria":
		return kind == "xray"
	default:
		return false
	}
}

func coreProvisionInbound(kind string, row Record) bool {
	protocol := value(row["protocol"])
	if !coreProvisionProtocol(kind, protocol) {
		return false
	}
	if protocol != "hysteria" {
		return true
	}
	settings, err := object(row["settings"])
	if err != nil || value(settings["version"]) != "2" {
		return false
	}
	stream, err := object(row["streamSettings"])
	if err != nil || stream["network"] != "hysteria" || stream["security"] != "tls" {
		return false
	}
	transport, err := object(stream["hysteriaSettings"])
	return err == nil && value(transport["version"]) == "2" && value(transport["auth"]) == ""
}

func coreCanProvision(kind string, doc, stats Record, protocol string) bool {
	if !coreProvisionProtocol(kind, protocol) {
		return false
	}
	if _, err := coreStatsAddress(kind, doc, stats); err != nil {
		return false
	}
	if kind == "xray" {
		policy, _ := doc["policy"].(Record)
		levels, _ := policy["levels"].(Record)
		level, _ := levels["0"].(Record)
		return level["statsUserUplink"] == true && level["statsUserDownlink"] == true
	}
	return true
}

func appendCoreStatsUser(input any, email string) []any {
	users, _ := input.([]any)
	if slices.Contains(anyStrings(users), email) {
		return users
	}
	return append(slices.Clone(users), email)
}

func extendCoreStats(kind string, doc, next, stats, binding Record) (Record, error) {
	tag := "mxioc-inbound-" + value(binding["inboundId"])
	email := value(binding["userEmail"])
	var protocol string
	for _, row := range anyRecords(next["inbounds"]) {
		if row["tag"] == tag {
			protocol = value(row["protocol"])
			if kind == "sing-box" {
				protocol = value(row["type"])
			}
		}
	}
	if !coreCanProvision(kind, doc, stats, protocol) {
		return nil, errors.New("当前入站协议或统计配置不支持创建独立用户")
	}
	updated := maps.Clone(stats)
	updated["users"] = appendCoreStatsUser(stats["users"], email)
	if kind == "sing-box" {
		experimental := maps.Clone(next["experimental"].(Record))
		api := maps.Clone(experimental["v2ray_api"].(Record))
		config := maps.Clone(api["stats"].(Record))
		config["users"] = appendCoreStatsUser(config["users"], email)
		api["stats"] = config
		experimental["v2ray_api"] = api
		next["experimental"] = experimental
	}
	groups, counts := coreCounterIndex(kind, next, updated)
	if counts[email] != 1 || !slices.Contains(groups[tag].emails, email) {
		return nil, errors.New("独立内核无法确认新用户的计数归属")
	}
	return updated, nil
}
