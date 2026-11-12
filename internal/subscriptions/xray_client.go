package subscriptions

import (
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

// Independent full Xray client configs, one per compatible node. No claim of
// translating Mihomo policies, DNS or privacy overrides into another core.
func convertXrayClient(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	configs := []any{}
	for _, node := range objects(source.Document["proxies"]) {
		out, e := remote.NodeOutbound(node, "proxy")
		if text(node["dialer-proxy"]) != "" {
			e = errors.New("链式节点请使用原始 Mihomo 配置")
		}
		if e != nil {
			result.Skipped = append(result.Skipped, Record{"name": node["name"], "type": node["type"], "reason": e.Error()})
			continue
		}
		configs = append(configs, Record{"remarks": node["name"], "log": Record{"loglevel": "warning"}, "inbounds": []any{Record{"tag": "socks", "listen": "127.0.0.1", "port": 10808, "protocol": "socks", "settings": Record{"auth": "noauth", "udp": true}}, Record{"tag": "http", "listen": "127.0.0.1", "port": 10809, "protocol": "http", "settings": Record{}}}, "outbounds": []any{out}, "routing": Record{"domainStrategy": "AsIs", "rules": []any{Record{"type": "field", "network": "tcp,udp", "outboundTag": "proxy"}}}})
	}
	result.Count = len(configs)
	if result.Count == 0 {
		return result, errors.New("没有兼容 Xray 的节点")
	}
	var e error
	result.Body, e = json.MarshalIndent(configs, "", "  ")
	return result, e
}
