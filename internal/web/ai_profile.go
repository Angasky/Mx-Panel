package web

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
	"strconv"
)

func aiProfileEdits(p aiAgentPlan) ([]config.ReviewedEdit, error) {
	if p.Script != "" || len(p.Params) != 1 || p.Params["edits"] == nil {
		return nil, errors.New("配置计划只能包含 edits 参数，不能携带脚本")
	}
	raw, err := json.Marshal(p.Params["edits"])
	if err != nil || len(raw) > 24000 {
		return nil, errors.New("配置计划超过长度限制")
	}
	var edits []config.ReviewedEdit
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&edits); err != nil || len(edits) == 0 || len(edits) > 20 {
		return nil, errors.New("配置计划须包含 1–20 项有效修改")
	}
	return edits, nil
}

// Probe only an existing node from the selected profile. Never accept an
// arbitrary model-supplied host or port, nor return credentials to the model.
func (s *Server) aiProbeNode(ctx context.Context, profile, name string) (string, error) {
	snapshot, err := s.repository.Snapshot(profile)
	if err != nil {
		return "", errors.New("订阅读取失败")
	}
	for _, item := range snapshot["nodes"].([]any) {
		node := item.(map[string]any)
		if node["name"] != name {
			continue
		}
		if node["type"] == "hysteria2" || node["type"] == "tuic" {
			return "此节点使用 QUIC/UDP，不能用 TCP 握手判断协议连通性。", nil
		}
		port, err := strconv.Atoi(fmt.Sprint(node["port"]))
		if err != nil {
			return "", errors.New("节点端口不支持 TCP 探测")
		}
		target := netprobe.Target{Method: "tcp", Name: "selected-node", Host: stringField(node, "server"), Port: port}
		if err = netprobe.Validate([]netprobe.Target{target}); err != nil {
			return "", errors.New("节点不是允许探测的公网目标")
		}
		result := netprobe.Measure(ctx, []netprobe.Target{target})
		raw, _ := json.Marshal(result)
		return "从面板所在服务器对所选节点进行 TCP 握手探测的实际结果（非客户端视角；不代表代理认证、TLS、UDP 或目标网站访问正常）：" + string(raw), nil
	}
	return "", errors.New("所选订阅中不存在该节点")
}

// Keep large subscriptions usable without claiming a partial view is complete.
func aiBoundedProfileContext(snapshot map[string]any) ([]byte, error) {
	keys := []string{"nodes", "groups", "rules", "dnsDomains"}
	counts := map[string]int{}
	for _, key := range keys {
		counts[key] = len(snapshot[key].([]any))
	}
	snapshot["counts"] = counts
	for {
		raw, err := json.Marshal(snapshot)
		if err != nil {
			return nil, errors.New("订阅结构序列化失败")
		}
		if len(raw) <= 48000 {
			return raw, nil
		}
		largest := ""
		size := 0
		for _, key := range keys {
			rows := snapshot[key].([]any)
			if len(rows) > 0 {
				data, _ := json.Marshal(rows)
				if len(data) > size {
					largest = key
					size = len(data)
				}
			}
		}
		if largest == "" {
			return nil, errors.New("订阅结构超过分析上限")
		}
		rows := snapshot[largest].([]any)
		snapshot[largest] = rows[:len(rows)/2]
		snapshot["truncated"] = true
	}
}
