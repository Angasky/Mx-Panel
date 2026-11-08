package subscriptions

import (
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"strconv"
)

func xrayFailover(item Record, nodes []Record, interval int) (Record, error) {
	if len(nodes) < 2 || len(nodes) > 8 {
		return nil, errors.New("Xray 主备需要 2–8 个路径")
	}
	outbounds := []any{}
	paths := []string{}
	for i, node := range nodes {
		tag := "mx-path-" + strconv.Itoa(i) + "/"
		out, err := remote.NodeOutbound(node, tag)
		if err != nil {
			return nil, err
		}
		outbounds = append(outbounds, out)
		paths = append(paths, tag)
	}
	outbounds = append(outbounds, Record{"tag": "mx-reject", "protocol": "blackhole", "settings": Record{}})
	balancers, rules := []any{}, []any{}
	for i, path := range paths {
		n := strconv.Itoa(i)
		next := "mx-reject"
		if i < len(paths)-1 {
			next = "mx-next-" + strconv.Itoa(i+1)
		}
		balancers = append(balancers, Record{"tag": "mx-balance-" + n, "selector": []any{path}, "fallbackTag": next, "strategy": Record{"type": "random"}})
		if i > 0 {
			outbounds = append(outbounds, Record{"tag": "mx-next-" + n, "protocol": "loopback", "settings": Record{"inboundTag": "mx-stage-" + n}})
			rules = append(rules, Record{"type": "field", "inboundTag": []any{"mx-stage-" + n}, "balancerTag": "mx-balance-" + n})
		}
	}
	rules = append(rules, Record{"type": "field", "network": "tcp,udp", "balancerTag": "mx-balance-0"})
	return Record{"remarks": item["name"], "log": Record{"loglevel": "warning"}, "inbounds": []any{Record{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": Record{"auth": "noauth", "udp": true}}, Record{"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": Record{}}}, "outbounds": outbounds, "routing": Record{"domainStrategy": "AsIs", "rules": rules, "balancers": balancers}, "observatory": Record{"subjectSelector": []any{"mx-path-"}, "probeURL": "https://www.gstatic.com/generate_204", "probeInterval": strconv.Itoa(interval) + "s", "enableConcurrency": true}}, nil
}
func convertXrayHA(source config.Subscription) (Export, error) {
	groups, skipped := managedHAGroups(source, func(node Record) error { _, err := remote.NodeOutbound(node, "check"); return err })
	result := Export{Skipped: skipped}
	configs := []any{}
	for _, group := range groups {
		doc, err := xrayFailover(group.item, group.nodes, group.interval)
		if err != nil {
			result.Skipped = append(result.Skipped, Record{"name": group.item["name"], "type": "fallback", "reason": err.Error()})
			continue
		}
		if label := usageLabel(source.Traffic); label != "" {
			doc["remarks"] = text(group.item["name"]) + " | " + label
		}
		configs = append(configs, doc)
	}
	if len(configs) == 0 {
		return result, errors.New("没有可导出的兼容 Xray 主备组")
	}
	raw, err := json.MarshalIndent(configs, "", "  ")
	if err != nil {
		return result, err
	}
	result.Body = raw
	result.Count = len(configs)
	return result, nil
}
