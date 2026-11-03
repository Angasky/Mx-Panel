package remote

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

func relayRecords(record Record) ([]Record, error) {
	if record["relays"] == nil {
		return []Record{}, nil
	}
	values, ok := record["relays"].([]any)
	if !ok {
		return nil, errors.New("中转归属列表无效")
	}
	result := []Record{}
	seen := map[string]bool{}
	for _, v := range values {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("中转归属记录无效")
		}
		id := value(row["inboundId"])
		n, e := strconv.Atoi(id)
		if e != nil || n < 1 || seen[id] || value(row["outboundTag"]) == "" {
			return nil, errors.New("中转归属 ID 或 tag 无效或重复")
		}
		seen[id] = true
		result = append(result, row)
	}
	return result, nil
}

// Proofs are derived from the durable creation snapshot, never browser input.
func relayOwnership(doc Record, tag, inTag string) (Record, error) {
	proof := Record{"inboundTag": inTag}
	outs, ok := doc["outbounds"].([]any)
	if !ok {
		return nil, errors.New("出站列表无效")
	}
	for _, v := range outs {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("出站格式无效")
		}
		if row["tag"] == tag {
			if proof["outboundHash"] != nil {
				return nil, errors.New("中转 tag 重复")
			}
			hash, e := identity(row)
			if e != nil {
				return nil, e
			}
			proof["outboundHash"] = hash
		}
	}
	routing, e := inboundObject(doc["routing"])
	if e != nil {
		return nil, e
	}
	for _, v := range anyRecords(routing["rules"]) {
		if v["outboundTag"] == tag {
			hash, e := identity(v)
			if e != nil {
				return nil, e
			}
			if proof["routeHash"] != nil {
				return nil, errors.New("中转出站被多个路由使用")
			}
			proof["routeHash"] = hash
		}
	}
	if proof["outboundHash"] == nil || proof["routeHash"] == nil || inTag == "" {
		return nil, errors.New("中转创建记录缺少资源身份")
	}
	return proof, nil
}

func stripOwnedRelay(doc, proof Record) (Record, bool, error) {
	tag := value(proof["outboundTag"])
	if !strings.HasPrefix(tag, "mxioc-relay-") || len(value(proof["outboundHash"])) != 64 || len(value(proof["routeHash"])) != 64 || value(proof["inboundTag"]) == "" {
		return nil, false, errors.New("旧中转缺少资源身份，未猜测删除远端配置")
	}
	raw, e := json.Marshal(doc)
	if e != nil {
		return nil, false, e
	}
	next, e := inboundObject(string(raw))
	if e != nil {
		return nil, false, e
	}
	outbounds, ok := next["outbounds"].([]any)
	if !ok {
		return nil, false, errors.New("出站列表无效")
	}
	kept := []any{}
	changed := false
	seen := false
	for _, v := range outbounds {
		out, ok := v.(map[string]any)
		if !ok {
			return nil, false, errors.New("出站格式无效")
		}
		if out["tag"] != tag {
			kept = append(kept, v)
			continue
		}
		hash, e := identity(out)
		if e != nil || hash != proof["outboundHash"] || seen {
			return nil, false, errors.New("中转出站身份变化或重复，未删除")
		}
		seen = true
		changed = true
	}
	next["outbounds"] = kept
	routing, e := inboundObject(next["routing"])
	if e != nil {
		return nil, false, e
	}
	rules := []any{}
	if routing["rules"] != nil {
		rules, ok = routing["rules"].([]any)
		if !ok {
			return nil, false, errors.New("路由列表无效")
		}
	}
	remaining := []any{}
	seen = false
	for _, v := range rules {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, false, errors.New("路由格式无效")
		}
		if row["outboundTag"] != tag {
			remaining = append(remaining, v)
			continue
		}
		hash, e := identity(row)
		tags := anyStrings(row["inboundTag"])
		if e != nil || hash != proof["routeHash"] || len(tags) != 1 || tags[0] != proof["inboundTag"] || seen {
			return nil, false, errors.New("中转路由身份变化或被其他入站引用，未删除")
		}
		seen = true
		changed = true
	}
	routing["rules"] = remaining
	next["routing"] = routing
	// Balancer selectors match prefixes, not only full tag equality.
	if raw := routing["balancers"]; raw != nil {
		values, ok := raw.([]any)
		if !ok || len(anyRecords(raw)) != len(values) {
			return nil, false, errors.New("负载组格式无效，未删除出站")
		}
	}
	for _, b := range anyRecords(routing["balancers"]) {
		if raw := b["selector"]; raw != nil {
			if _, ok := raw.([]any); !ok {
				return nil, false, errors.New("负载组选择器格式无效")
			}
		}
		for _, prefix := range anyStrings(b["selector"]) {
			if strings.HasPrefix(tag, prefix) {
				return nil, false, errors.New("中转出站仍被负载组引用，未删除")
			}
		}
	}
	var references func(any) bool
	references = func(v any) bool {
		switch x := v.(type) {
		case string:
			return x == tag
		case map[string]any:
			for _, v := range x {
				if references(v) {
					return true
				}
			}
		case []any:
			for _, v := range x {
				if references(v) {
					return true
				}
			}
		}
		return false
	}
	if references(next) {
		return nil, false, errors.New("中转出站仍被其他配置引用，未删除")
	}
	return next, changed, nil
}

func (m *Manager) markRelayDeleting(server string, proof Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return e
	}
	record, e := find(data, server)
	if e != nil {
		return e
	}
	rows, e := relayRecords(record)
	if e != nil {
		return e
	}
	for _, row := range rows {
		if value(row["inboundId"]) == value(proof["inboundId"]) {
			if row["outboundTag"] != proof["outboundTag"] || row["outboundHash"] != proof["outboundHash"] || row["routeHash"] != proof["routeHash"] {
				return errors.New("中转归属已变化")
			}
			row["deletePending"] = true
			row["status"] = "deleting"
			return m.flush(data)
		}
	}
	return errors.New("中转归属不存在")
}
func (m *Manager) finishRelayDelete(server string, proof Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return e
	}
	record, e := find(data, server)
	if e != nil {
		return e
	}
	keep := []any{}
	rows, e := relayRecords(record)
	if e != nil {
		return e
	}
	for _, row := range rows {
		if value(row["inboundId"]) == value(proof["inboundId"]) {
			if row["outboundTag"] != proof["outboundTag"] || row["deletePending"] != true || row["outboundHash"] != proof["outboundHash"] || row["routeHash"] != proof["routeHash"] || row["inboundTag"] != proof["inboundTag"] {
				return errors.New("中转清理代次已变化")
			}
			continue
		}
		keep = append(keep, row)
	}
	record["relays"] = keep
	return m.flush(data)
}
func cleanupPanelRelay(ctx context.Context, p *Panel, proof Record) error {
	id, e := strconv.Atoi(value(proof["inboundId"]))
	if e != nil || id < 1 {
		return errors.New("中转入站 ID 无效")
	}
	_, exists, e := panelInbound(ctx, p, id)
	if e != nil {
		return e
	}
	if exists {
		return errors.New("中转入站仍存在，暂不移除其出站路由")
	}
	before, wrapper, e := readPanelConfig(ctx, p)
	if e != nil {
		return e
	}
	next, changed, e := stripOwnedRelay(before, proof)
	if e != nil {
		return e
	}
	latest, _, e := readPanelConfig(ctx, p)
	if e != nil {
		return e
	}
	a, e := identity(before)
	if e != nil {
		return e
	}
	b, e := identity(latest)
	if e != nil || a != b {
		return errors.New("配置发生并发修改，保留待清理记录")
	}
	if changed {
		if e = writePanelConfig(ctx, p, next, wrapper); e != nil {
			return errors.New("中转资源清理结果待核对，请刷新后重试")
		}
	} else {
		if _, e = p.RequestOnce(ctx, "panel/api/server/restartXrayService", Record{}); e != nil {
			return errors.New("中转资源已移除，服务状态待核对")
		}
	}
	actual, _, e := readPanelConfig(ctx, p)
	if e != nil {
		return e
	}
	_, stillPresent, e := stripOwnedRelay(actual, proof)
	if e != nil {
		return e
	}
	if stillPresent {
		return errors.New("中转资源移除未确认")
	}
	return nil
}

func (m *Manager) deleteRelayInbound(ctx context.Context, p *Panel, record, proof Record, id int, expected string, guard func(Record) error) (Record, error) {
	config, _, e := readPanelConfig(ctx, p)
	if e != nil {
		return nil, e
	}
	if _, _, e = stripOwnedRelay(config, proof); e != nil {
		return nil, e
	}
	filtered := Record{}
	for k, v := range record {
		if k != "relays" {
			filtered[k] = v
		}
	}
	result, e := deletePanelInbound(ctx, p, filtered, id, expected, func(old Record) error {
		if old != nil && old["tag"] != proof["inboundTag"] {
			return errors.New("中转入站 tag 已变化")
		}
		if e := guard(old); e != nil {
			return e
		}
		return m.markRelayDeleting(value(record["id"]), proof)
	})
	if e != nil {
		return nil, e
	}
	if e = cleanupPanelRelay(ctx, p, proof); e != nil {
		return nil, e
	}
	if e = m.finishRelayDelete(value(record["id"]), proof); e != nil {
		return nil, e
	}
	result["relayCleaned"] = true
	return result, nil
}
