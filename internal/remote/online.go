package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// OnlineUser reads authenticated-user observations, never socket/port totals.
func (m *Manager) OnlineUser(ctx context.Context, id string, binding Record) (Record, error) {
	if binding["scope"] != "user" || binding["serverId"] != id {
		return nil, errors.New("需要独立认证用户绑定")
	}
	record, e := m.Record(id)
	if e != nil {
		return nil, e
	}
	if record["installType"] != "xray" {
		return nil, errors.New("该内核暂不提供已适配的逐用户在线 IP 接口（不使用端口连接数推算）")
	}
	if binding["dedicated"] == true {
		return nil, errors.New("专属端口绑定暂不支持逐用户在线统计")
	}
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		saved, e := m.Secret(record, "coreState")
		if e != nil {
			return nil, e
		}
		state, e := parseLegacyCoreState(saved)
		if e != nil {
			return nil, e
		}
		before, doc, e := readCore(ctx, kind, run)
		if e != nil {
			return nil, e
		}
		// Reuse strict managed inbound and authenticated credential ownership checks.
		checked, e := readCoreUser(ctx, kind, state, binding, run)
		if e != nil {
			return nil, e
		}
		if checked["counterError"] != nil {
			return nil, errors.New("用户统计归属无法核对，请先检查用户计量")
		}
		address, e := coreStatsAddress(kind, doc, state.UserStats)
		if e != nil {
			return nil, e
		}
		raw, e := run(ctx, "/usr/local/bin/xray api statsonlineiplist --server="+quote(address)+" -email "+quote(value(binding["userEmail"])), 256<<10)
		if e != nil {
			return nil, errors.New("Xray 在线统计不可用：需支持 statsonlineiplist，并启用该用户级别 statsUserOnline；未创建在线记录时也可能返回不可用")
		}
		result, e := parseOnlineIPs(raw, value(binding["userEmail"]))
		if e != nil {
			return nil, e
		}
		after, _, e := readCore(ctx, kind, run)
		if e != nil || !bytes.Equal(before, after) {
			return nil, errors.New("采集期间配置变化，请重新刷新")
		}
		return result, nil
	})
}
func parseOnlineIPs(raw, email string) (Record, error) {
	bad := errors.New("在线 IP 响应无效")
	var doc struct {
		Name string                     `json:"name"`
		IPs  map[string]json.RawMessage `json:"ips"`
	}
	if len(raw) > 256<<10 || json.Unmarshal([]byte(raw), &doc) != nil || doc.Name != "user>>>"+email+">>>online" || len(doc.IPs) > 2048 {
		return nil, bad
	}
	merged := map[string]int64{}
	for value, stamp := range doc.IPs {
		ip, e := netip.ParseAddr(strings.Trim(value, "[]"))
		if e != nil || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, bad
		}
		v := string(stamp)
		if strings.HasPrefix(v, "\"") {
			if json.Unmarshal(stamp, &v) != nil {
				return nil, bad
			}
		}
		n, e := strconv.ParseInt(v, 10, 64)
		if e != nil || n < 0 {
			return nil, bad
		}
		key := ip.Unmap().String()
		if old, ok := merged[key]; !ok || n > old {
			merged[key] = n
		}
	}
	keys := make([]string, 0, len(merged))
	for ip := range merged {
		keys = append(keys, ip)
	}
	sort.Strings(keys)
	rows := []any{}
	for _, ip := range keys {
		rows = append(rows, Record{"ip": ip, "lastSeen": merged[ip]})
	}
	return Record{"ips": rows, "source": "xray-online-map"}, nil
}

// EnableOnlineUser explicitly enables the user's policy level. The existing
// config transaction validates and restores the previous file on startup failure.
func (m *Manager) EnableOnlineUser(ctx context.Context, id string, binding Record) (Record, error) {
	if binding["scope"] != "user" || binding["serverId"] != id || binding["dedicated"] == true {
		return nil, errors.New("需要独立认证用户绑定")
	}
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		if kind != "xray" {
			return nil, errors.New("目前仅支持独立 Xray 在线统计")
		}
		saved, e := m.Secret(record, "coreState")
		if e != nil {
			return nil, e
		}
		state, e := parseLegacyCoreState(saved)
		if e != nil {
			return nil, e
		}
		raw, doc, e := readCore(ctx, kind, run)
		if e != nil {
			return nil, e
		}
		checked, e := readCoreUser(ctx, kind, state, binding, run)
		if e != nil {
			return nil, e
		}
		if checked["counterError"] != nil {
			return nil, errors.New("请先启用并核对用户计量")
		}

		current, _, e := readCore(ctx, kind, run)
		if e != nil || !bytes.Equal(raw, current) {
			return nil, errors.New("采集期间配置变化，请重试")
		}
		// Native managed users use level zero unless a level is explicitly present.
		client, _ := checked["client"].(Record)
		level := value(client["level"])
		if level == "" {
			level = "0"
		}
		if n, e := strconv.ParseUint(level, 10, 32); e != nil || strconv.FormatUint(n, 10) != level {
			return nil, errors.New("用户策略级别无效")
		}
		policy, e := coreConfigObject(doc, "policy")
		if e != nil {
			return nil, e
		}
		levels, e := coreConfigObject(policy, "levels")
		if e != nil {
			return nil, e
		}
		settings, e := coreConfigObject(levels, level)
		if e != nil {
			return nil, e
		}
		if settings["statsUserOnline"] == true {
			return Record{"enabled": true, "changed": false}, nil
		}
		settings["statsUserOnline"] = true
		levels[level] = settings
		policy["levels"] = levels
		doc["policy"] = policy
		if _, e = applyCore(ctx, kind, raw, doc, "", run); e != nil {
			return nil, e
		}
		return Record{"enabled": true, "changed": true}, nil
	})
}
