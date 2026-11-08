package subscriptions

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func convertSingBox(source config.Subscription) (Export, error) {
	result := Export{Skipped: []Record{}}
	nodes := []any{}
	tags := []string{}
	for index, node := range objects(source.Document["proxies"]) {
		tag := fmt.Sprintf("mx-%d %s", index+1, text(node["name"]))
		outbound, err := remote.SingBoxOutbound(node, tag)
		if text(node["dialer-proxy"]) != "" {
			err = errors.New("链式节点请使用完整 Mihomo 配置")
		}
		if err != nil {
			result.Skipped = append(result.Skipped, Record{"name": node["name"], "type": node["type"], "reason": err.Error()})
			continue
		}
		nodes = append(nodes, outbound)
		tags = append(tags, tag)
	}
	result.Count = len(nodes)
	if result.Count == 0 {
		return result, errors.New("没有兼容 sing-box 的节点")
	}
	outbounds := []any{Record{"type": "selector", "tag": "PROXY", "outbounds": tags, "default": tags[0]}}
	outbounds = append(outbounds, nodes...)
	doc := Record{
		"log":       Record{"level": "warn"},
		"inbounds":  []any{Record{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}},
		"outbounds": outbounds,
		"route":     Record{"final": "PROXY"},
	}
	var err error
	result.Body, err = json.MarshalIndent(doc, "", "  ")
	return result, err
}
