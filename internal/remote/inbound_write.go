package remote

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
)

var inboundFields = []string{"up", "down", "total", "remark", "enable", "expiryTime", "listen", "port", "protocol", "settings", "streamSettings", "sniffing", "allocate"}

func inboundObject(raw any) (Record, error) {
	if raw == nil {
		return Record{}, nil
	}
	if text, ok := raw.(string); ok {
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		var doc Record
		if decoder.Decode(&doc) != nil || doc == nil {
			return nil, errors.New("入站 JSON 配置无效")
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return nil, errors.New("入站 JSON 含多余内容")
		}
		return doc, nil
	}
	if doc, ok := raw.(map[string]any); ok {
		return doc, nil
	}
	return nil, errors.New("入站配置必须为 JSON 对象")
}

// InboundVersion ignores counters, but includes all editable configuration and
// clients. It is a local compare token, not an upstream transactional CAS.
func InboundVersion(row Record) (string, error) {
	data := Record{"id": row["id"], "tag": row["tag"]}
	for _, key := range inboundFields {
		if key == "up" || key == "down" {
			continue
		}
		if key == "settings" || key == "streamSettings" || key == "sniffing" {
			doc, err := inboundObject(row[key])
			if err != nil {
				return "", err
			}
			data[key] = doc
		} else {
			data[key] = row[key]
		}
	}
	return identity(data)
}

func prepareInboundEdit(old, payload Record) (Record, Record, error) {
	if payload == nil {
		return nil, nil, errors.New("入站配置必须为 JSON 对象")
	}
	next := Record{}
	for k, v := range old {
		next[k] = v
	}
	for _, key := range inboundFields {
		if v, ok := payload[key]; ok && key != "up" && key != "down" {
			next[key] = v
		}
	}
	port, err := parsedPort(next["port"], 0)
	if err != nil || port < 1 {
		return nil, nil, errors.New("入站端口必须为 1–65535")
	}
	next["port"] = port
	protocols := map[string]bool{"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "socks": true, "http": true, "dokodemo-door": true, "mixed": true, "tunnel": true, "hysteria": true, "hysteria2": true, "tuic": true}
	if !protocols[value(next["protocol"])] {
		return nil, nil, errors.New("入站协议未适配")
	}
	if enabled, exists := next["enable"]; exists {
		if _, ok := enabled.(bool); !ok {
			return nil, nil, errors.New("入站启用状态必须为布尔值")
		}
	}
	body := Record{}
	for _, key := range inboundFields {
		v, exists := next[key]
		if !exists {
			continue
		}
		if key == "settings" || key == "streamSettings" || key == "sniffing" {
			doc, err := inboundObject(v)
			if err != nil {
				return nil, nil, err
			}
			if key == "settings" {
				if clients, exists := doc["clients"]; exists {
					list, ok := clients.([]any)
					if !ok {
						return nil, nil, errors.New("入站用户列表格式无效")
					}
					for _, client := range list {
						if _, ok := client.(map[string]any); !ok {
							return nil, nil, errors.New("入站用户格式无效")
						}
					}
				}
			}
			raw, err := json.Marshal(doc)
			if err != nil {
				return nil, nil, errors.New("入站 JSON 配置无法编码")
			}
			body[key] = string(raw)
			next[key] = doc
		} else {
			body[key] = v
		}
	}
	wire, err := json.Marshal(body)
	if err != nil || len(wire) > 256<<10 {
		return nil, nil, errors.New("单条入站配置不能超过 256 KB")
	}
	return body, next, nil
}

func panelInbound(ctx context.Context, panel *Panel, id int) (Record, bool, error) {
	raw, err := panel.Request(ctx, "panel/api/inbounds/list", nil, "")
	if err != nil {
		return nil, false, err
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, false, errors.New("面板未返回完整入站列表")
	}
	seen := map[int]bool{}
	var found Record
	for _, v := range values {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, false, errors.New("入站列表格式异常")
		}
		n, err := strconv.Atoi(value(row["id"]))
		if err != nil || n <= 0 || seen[n] {
			return nil, false, errors.New("入站 ID 无效或重复")
		}
		seen[n] = true
		if n == id {
			found = row
		}
	}
	return found, found != nil, nil
}
func dependentInbound(record Record, id int) bool {
	for _, key := range []string{"bandwidths", "meters"} {
		if values, ok := record[key].(map[string]any); ok {
			if _, exists := values[strconv.Itoa(id)]; exists {
				return true
			}
		}
	}
	for _, v := range anyRecords(record["relays"]) {
		if value(v["inboundId"]) == strconv.Itoa(id) {
			return true
		}
	}
	return false
}
func anyRecords(value any) []Record {
	result := []Record{}
	if list, ok := value.([]any); ok {
		for _, v := range list {
			if row, ok := v.(map[string]any); ok {
				result = append(result, row)
			}
		}
	}
	return result
}

func editPanelInbound(ctx context.Context, panel *Panel, record Record, id int, payload Record, expected string, guard func(Record, Record) error) (Record, error) {
	for _, relay := range anyRecords(record["relays"]) {
		if value(relay["inboundId"]) == strconv.Itoa(id) && relay["deletePending"] == true {
			return nil, errors.New("中转正在删除或清理，暂不编辑或启停")
		}
	}
	old, exists, err := panelInbound(ctx, panel, id)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.New("远端入站已不存在，请刷新列表")
	}
	version, err := InboundVersion(old)
	if err != nil {
		return nil, err
	}
	if expected == "" || version != expected {
		return nil, errors.New("入站配置已变化，请刷新列表后重新编辑")
	}
	body, next, err := prepareInboundEdit(old, payload)
	if err != nil {
		return nil, err
	}
	if dependentInbound(record, id) {
		a, e := EndpointIdentity(old)
		if e != nil {
			return nil, e
		}
		b, e := EndpointIdentity(next)
		if e != nil {
			return nil, e
		}
		if a != b {
			return nil, errors.New("入站关联限速、计量或中转配置，请保持端口和传输配置不变")
		}
	}
	if err = guard(old, next); err != nil {
		return nil, err
	}
	if _, err = panel.RequestOnce(ctx, "panel/api/inbounds/update/"+strconv.Itoa(id), body); err != nil {
		return nil, err
	}
	actual, present, err := panelInbound(ctx, panel, id)
	if err != nil || !present {
		return nil, errors.New("修改已下发，但结果待核对，请刷新列表；未自动重放请求")
	}
	want, _ := InboundVersion(next)
	got, err := InboundVersion(actual)
	if err != nil || want != got {
		return nil, errors.New("面板保存结果与预期不一致，请刷新列表核对；未自动重放请求")
	}
	return Record{"updated": true}, nil
}
func deletePanelInbound(ctx context.Context, panel *Panel, record Record, id int, expected string, guard func(Record) error) (Record, error) {
	old, exists, err := panelInbound(ctx, panel, id)
	if err != nil {
		return nil, err
	}
	if expected == "" {
		return nil, errors.New("缺少入站身份，请刷新列表")
	}
	if dependentInbound(record, id) {
		return nil, errors.New("该入站仍关联限速、计量或中转配置，清理适配尚未完成，未删除远端入站")
	}
	if exists {
		version, err := InboundVersion(old)
		if err != nil {
			return nil, err
		}
		if version != expected {
			return nil, errors.New("远端入站身份已变化，请刷新后重新确认删除")
		}
	}
	if err = guard(old); err != nil {
		return nil, err
	}
	if !exists {
		return Record{"deleted": true, "alreadyMissing": true}, nil
	}
	if _, err = panel.RequestOnce(ctx, "panel/api/inbounds/del/"+strconv.Itoa(id), Record{}); err != nil {
		return nil, err
	}
	_, present, err := panelInbound(ctx, panel, id)
	if err != nil || present {
		return nil, errors.New("删除已下发，但结果待核对，请刷新列表；未自动重放请求")
	}
	return Record{"deleted": true}, nil
}
func (m *Manager) UpdateInbound(ctx context.Context, server string, id int, payload Record, expected string, guard func(Record, Record) error) (Record, error) {
	if id < 1 {
		return nil, errors.New("入站 ID 无效")
	}
	record, err := m.Record(server)
	if err != nil {
		return nil, err
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		return m.writeManagedCoreInbound(ctx, server, id, expected, payload, guard, nil, false)
	}
	result, err := m.WithPanel(ctx, server, func(panel *Panel, record Record) (any, error) {
		return editPanelInbound(ctx, panel, record, id, payload, expected, guard)
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}
func (m *Manager) DeleteInbound(ctx context.Context, server string, id int, expected string, guard func(Record) error) (Record, error) {
	if id < 1 {
		return nil, errors.New("入站 ID 无效")
	}
	record, err := m.Record(server)
	if err != nil {
		return nil, err
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		return m.writeManagedCoreInbound(ctx, server, id, expected, nil, nil, guard, false)
	}
	return m.deleteInbound(ctx, server, id, expected, guard, false)
}

func (m *Manager) DeleteNamedRelay(ctx context.Context, server string, id int, expected string, guard func(Record) error) (Record, error) {
	record, err := m.Record(server)
	if err != nil {
		return nil, err
	}
	if value(record["installType"]) == "xray" {
		return m.writeManagedCoreInbound(ctx, server, id, expected, nil, nil, guard, true)
	}
	return m.deleteInbound(ctx, server, id, expected, guard, true)
}

func (m *Manager) deleteInbound(ctx context.Context, server string, id int, expected string, guard func(Record) error, requireRelay bool) (Record, error) {
	if id < 1 {
		return nil, errors.New("入站 ID 无效")
	}
	result, err := m.WithPanel(ctx, server, func(panel *Panel, record Record) (any, error) {
		relays, e := relayRecords(record)
		if e != nil {
			return nil, e
		}
		for _, relay := range relays {
			if value(relay["inboundId"]) == strconv.Itoa(id) {
				return m.deleteRelayInbound(ctx, panel, record, relay, id, expected, guard)
			}
		}
		if requireRelay {
			_, exists, err := panelInbound(ctx, panel, id)
			if err != nil {
				return nil, err
			}
			if exists {
				return nil, errors.New("入站不属于总控中转，未删除")
			}
			if err := guard(nil); err != nil {
				return nil, err
			}
			return Record{"deleted": true, "alreadyMissing": true}, nil
		}
		return deletePanelInbound(ctx, panel, record, id, expected, guard)
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}
