package remote

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func readPanelConfig(ctx context.Context, p *Panel) (Record, Record, error) {
	raw, err := p.Request(ctx, "panel/xray/", Record{}, "")
	if err != nil {
		return nil, nil, err
	}
	wrapper, err := inboundObject(raw)
	if err != nil {
		return nil, nil, err
	}
	if wrapper["xraySetting"] == nil {
		return nil, nil, errors.New("面板未返回完整 Xray 配置")
	}
	doc, err := inboundObject(wrapper["xraySetting"])
	return doc, wrapper, err
}
func relayPatch(original, inbound, outbound Record) (Record, error) {
	raw, err := json.Marshal(original)
	if err != nil {
		return nil, err
	}
	changed, err := inboundObject(string(raw))
	if err != nil {
		return nil, err
	}
	outbounds, ok := changed["outbounds"].([]any)
	if !ok {
		return nil, errors.New("Xray 出站列表无效")
	}
	tag := value(outbound["tag"])
	inTag := value(inbound["tag"])
	if tag == "" || inTag == "" {
		return nil, errors.New("中转入站或出站 tag 缺失")
	}
	for _, v := range outbounds {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("Xray 出站格式无效")
		}
		if row["tag"] == tag {
			return nil, errors.New("中转出站 tag 已被占用")
		}
	}
	routing, err := inboundObject(changed["routing"])
	if err != nil {
		return nil, err
	}
	rules := []any{}
	if routing["rules"] != nil {
		rules, ok = routing["rules"].([]any)
		if !ok {
			return nil, errors.New("Xray 路由列表无效")
		}
	}
	for _, v := range rules {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("Xray 路由格式无效")
		}
		if value(row["inboundTag"]) == inTag {
			return nil, errors.New("此入站已有路由，未覆盖")
		}
		for _, tag := range anyStrings(row["inboundTag"]) {
			if tag == inTag {
				return nil, errors.New("此入站已有路由，未覆盖")
			}
		}
	}
	changed["outbounds"] = append(outbounds, outbound)
	routing["rules"] = append([]any{Record{"type": "field", "inboundTag": []any{inTag}, "outboundTag": tag}}, rules...)
	changed["routing"] = routing
	return changed, nil
}
func anyStrings(raw any) []string {
	result := []string{}
	if list, ok := raw.([]any); ok {
		for _, v := range list {
			if s, ok := v.(string); ok {
				result = append(result, s)
			}
		}
	}
	return result
}
func writePanelConfig(ctx context.Context, p *Panel, doc, wrapper Record) error {
	raw, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	test := value(wrapper["outboundTestUrl"])
	if test == "" {
		test = "https://www.google.com/generate_204"
	}
	if _, err = p.RequestOnce(ctx, "panel/xray/update", Record{"xraySetting": string(raw), "outboundTestUrl": test}); err != nil {
		return err
	}
	_, err = p.RequestOnce(ctx, "panel/api/server/restartXrayService", Record{})
	return err
}
func applyPanelRelay(ctx context.Context, p *Panel, entry Record, persist func(Record) error) error {
	desired, err := inboundObject(entry["desired"])
	if err != nil {
		return err
	}
	original, err := inboundObject(desired["original"])
	if err != nil {
		return err
	}
	updated, err := inboundObject(desired["updated"])
	if err != nil {
		return err
	}
	before, wrapper, err := readPanelConfig(ctx, p)
	if err != nil {
		return err
	}
	actual, err := identity(before)
	if err != nil {
		return err
	}
	old, err := identity(original)
	if err != nil {
		return err
	}
	next, err := identity(updated)
	if err != nil {
		return err
	}
	if entry["status"] != "prepared" && entry["status"] != "sent" && entry["status"] != "confirmed" {
		return errors.New("中转创建状态无效")
	}
	if entry["status"] == "confirmed" {
		if actual != next {
			return errors.New("中转配置已变化，请核对远端")
		}
		return nil
	}
	if entry["status"] == "sent" {
		if actual != next {
			return errors.New("中转请求结果待核对，未重复覆盖配置")
		}
		if _, err = p.RequestOnce(ctx, "panel/api/server/restartXrayService", Record{}); err != nil {
			return errors.New("中转配置已保存，服务重启待核对")
		}
	}
	if entry["status"] == "prepared" {
		if actual != old {
			return errors.New("Xray 配置已变化，未覆盖其他操作")
		}
		entry["status"] = "sent"
		if err = persist(entry); err != nil {
			return err
		}
		if err = writePanelConfig(ctx, p, updated, wrapper); err != nil {
			current, _, e := readPanelConfig(ctx, p)
			hash, _ := identity(current)
			if e == nil && hash == next {
				if e = writePanelConfig(ctx, p, original, wrapper); e == nil {
					restored, _, e := readPanelConfig(ctx, p)
					hash, _ := identity(restored)
					if e == nil && hash == old {
						entry["status"] = "prepared"
						if persist(entry) == nil {
							return errors.New("中转应用失败，已恢复原配置；空用户入口保留供重试")
						}
					}
				}
			}
			return errors.New("中转应用或回滚结果待核对，未自动重复写入")
		}
	}
	current, _, err := readPanelConfig(ctx, p)
	if err != nil {
		return err
	}
	hash, _ := identity(current)
	if hash != next {
		return errors.New("中转保存结果不一致，请核对远端")
	}
	entry["status"] = "confirmed"
	return persist(entry)
}
func (m *Manager) recordRelay(server string, inbound Record, tag, status string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	record, err := find(data, server)
	if err != nil {
		return err
	}
	if raw := record["relays"]; raw != nil {
		list, ok := raw.([]any)
		if !ok || len(anyRecords(raw)) != len(list) {
			return errors.New("已有中转归属记录无效，未覆盖")
		}
	}
	rows := anyRecords(record["relays"])
	for _, row := range rows {
		if value(row["inboundId"]) == value(inbound["id"]) {
			if row["outboundTag"] != tag {
				return errors.New("入站已有其他中转归属")
			}
			row["status"] = status
			return m.flush(data)
		}
	}
	record["relays"] = appendRecord(rows, Record{"inboundId": inbound["id"], "outboundTag": tag, "status": status})
	return m.flush(data)
}
func appendRecord(rows []Record, row Record) []any {
	result := []any{}
	for _, r := range rows {
		result = append(result, r)
	}
	return append(result, row)
}

func (m *Manager) CreateRelay(ctx context.Context, server, scope string, payload Record) (Record, error) {
	landing, err := links.Parse(value(payload["landingLink"]))
	if err != nil {
		return nil, errors.New("落地节点链接无效或未适配")
	}
	key, hash, err := createRequestIdentity(scope, payload)
	if err != nil {
		return nil, err
	}
	tag := "mxioc-relay-" + key[:16]
	outbound, err := NodeOutbound(landing, tag)
	if err != nil {
		return nil, err
	}
	if templateName(payload) != "vless-reality" {
		return nil, errors.New("中转入口仅支持 Reality 模板")
	}
	created, err := m.CreateInbound(ctx, server, scope, payload)
	if err != nil {
		return nil, err
	}
	inbound := created["inbound"].(Record)
	id, e := strconv.Atoi(value(inbound["id"]))
	if e != nil || id < 1 {
		return nil, errors.New("中转入站 ID 无效")
	}
	journalKey, _ := identity([]any{key, "relay"})
	result, err := m.WithPanel(ctx, server, func(p *Panel, record Record) (any, error) {
		fresh, exists, e := panelInbound(ctx, p, id)
		if e != nil {
			return nil, e
		}
		if !exists {
			return nil, errors.New("中转入口已不存在")
		}
		expected, e := EndpointIdentity(inbound)
		if e != nil {
			return nil, e
		}
		actual, e := EndpointIdentity(fresh)
		if e != nil || expected != actual {
			return nil, errors.New("中转入口身份已变化")
		}
		inbound = fresh
		created["inbound"] = fresh
		entry, e := m.loadCreate(journalKey)
		if e != nil {
			return nil, e
		}
		if entry == nil {
			settings, e := inboundObject(inbound["settings"])
			if e != nil {
				return nil, e
			}
			clients, ok := settings["clients"].([]any)
			if !ok || len(clients) != 0 {
				return nil, errors.New("中转准备前入口已有用户，未改写路由")
			}
			original, _, e := readPanelConfig(ctx, p)
			if e != nil {
				return nil, e
			}
			updated, e := relayPatch(original, inbound, outbound)
			if e != nil {
				return nil, e
			}
			entry = Record{"serverId": server, "scope": scope, "revision": createServerRevision(record), "requestHash": hash, "status": "prepared", "desired": Record{"original": original, "updated": updated}}
		} else {
			if entry["serverId"] != server || entry["scope"] != scope || entry["revision"] != createServerRevision(record) || entry["requestHash"] != hash {
				return nil, errors.New("中转服务器或请求已变化")
			}
			doc, e := m.OpenUser(value(entry["sealedDesired"]))
			if e != nil {
				return nil, e
			}
			entry["desired"] = doc
		}
		persist := func(v Record) error { return m.persistCreate(journalKey, v) }
		if e = persist(entry); e != nil {
			return nil, e
		}
		if e = m.recordRelay(server, inbound, tag, "pending"); e != nil {
			return nil, e
		}
		if e = applyPanelRelay(ctx, p, entry, persist); e != nil {
			return nil, e
		}
		if e = m.recordRelay(server, inbound, tag, "active"); e != nil {
			return nil, e
		}
		return created, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(Record), nil
}
