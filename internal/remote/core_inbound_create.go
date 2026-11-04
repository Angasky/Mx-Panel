package remote

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
)

const coreInboundCreate = "core-inbound-create"

func nativeCorePortUsed(doc Record, port int) bool {
	for _, row := range anyRecords(doc["inbounds"]) {
		if value(row["port"]) == strconv.Itoa(port) || value(row["listen_port"]) == strconv.Itoa(port) {
			return true
		}
	}
	return false
}

func (m *Manager) createStandaloneInbound(ctx context.Context, server, key, requestHash string, payload, outbound Record) (Record, error) {
	return m.withCore(ctx, server, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.createCoreInbound(ctx, server, kind, key, requestHash, record, payload, outbound, run)
	})
}

func (m *Manager) createCoreInbound(ctx context.Context, server, kind, key, requestHash string, record, payload, outbound Record, run coreRunner) (Record, error) {
	template := templateName(payload)
	protocol := standaloneTemplateProtocol(kind, template)
	if protocol == "" || payload["inbound"] != nil || (payload["landingLink"] != nil && outbound == nil) ||
		(outbound != nil && ((kind == "xray" && template != "vless-reality") || (kind == "sing-box" && template != "vmess-tcp"))) {
		return nil, errors.New("当前独立内核不支持此托管入站模板")
	}
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	stateDoc := Record{"inbounds": []any{}, "outbounds": []any{}, "routing": Record{"rules": []any{}}}
	if stateToken != "" {
		saved, err := m.Secret(record, "coreState")
		if err != nil {
			return nil, err
		}
		stateDoc, err = inboundObject(saved)
		if err != nil {
			return nil, err
		}
	}
	rows, ok := stateDoc["inbounds"].([]any)
	if !ok {
		return nil, errors.New("独立内核托管列表格式无效")
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	var live []any
	if input, exists := doc["inbounds"]; exists {
		live, ok = input.([]any)
		if !ok || len(anyRecords(input)) != len(live) {
			return nil, errors.New("独立内核远端入站格式无效")
		}
	}
	for _, item := range rows {
		row, ok := item.(Record)
		if !ok {
			return nil, errors.New("独立内核托管入站格式无效")
		}
		if row["goCreateKey"] != key {
			continue
		}
		if row["goCreateHash"] != requestHash || row["enable"] == false {
			return nil, errors.New("创建请求配置已变化或入站已停用")
		}
		expected, err := legacyNativeInbound(kind, row)
		if err != nil {
			return nil, err
		}
		matched := 0
		for _, item := range live {
			actual := item.(Record)
			if actual["tag"] != row["tag"] {
				continue
			}
			if !sameCoreInbound(expected, actual) {
				return nil, errors.New("同一请求的远端入站配置已变化")
			}
			matched++
		}
		if matched != 1 {
			return nil, errors.New("同一请求的远端入站缺失或重复")
		}
		if err := verifyCoreRelay(doc, row); err != nil {
			return nil, err
		}
		return Record{"inbound": row, "reused": true}, nil
	}
	before := coreConfigHash(raw)
	journal, _, err := m.coreUserJournal(pending, key, coreInboundCreate, before)
	if err != nil {
		return nil, err
	}
	var row Record
	if journal != nil {
		row, ok = journal["row"].(Record)
		if !ok || row["goCreateKey"] != key || row["goCreateHash"] != requestHash {
			return nil, errors.New("独立内核待创建的入站配置已变化")
		}
	} else {
		stats, _ := stateDoc["userStats"].(Record)
		if len(stats) == 0 {
			if _, err := planCoreStats(kind, doc); err != nil {
				return nil, err
			}
			if err := checkCoreStatsTools(ctx, kind, run); err != nil {
				return nil, err
			}
		} else {
			if !coreCanProvision(kind, doc, stats, protocol) {
				return nil, errors.New("现有统计配置不支持此模板的独立用户")
			}
			if _, err := queryCoreCounters(ctx, kind, doc, stats, run); err != nil {
				return nil, err
			}
		}
		prepared, address, err := m.templatePayload(server, record, payload)
		if err != nil {
			return nil, err
		}
		row, err = buildInboundTemplate(prepared, address)
		if err != nil {
			return nil, err
		}
		if protocol == "hysteria2" {
			row["protocol"] = "hysteria2"
			delete(row["settings"].(Record), "version")
			stream := row["streamSettings"].(Record)
			stream["network"] = "tcp"
			delete(stream, "hysteriaSettings")
		}
		port, _ := strconv.Atoi(value(row["port"]))
		if value(payload["port"]) == "" {
			for attempt := 0; attempt < 128 && nativeCorePortUsed(doc, port); attempt++ {
				port, err = randomInboundPort()
				if err != nil {
					return nil, err
				}
			}
		}
		if nativeCorePortUsed(doc, port) {
			return nil, errors.New("监听端口已被远端入站使用")
		}
		decoded, err := hex.DecodeString(key)
		if err != nil || len(decoded) < 4 {
			return nil, errors.New("独立内核创建标识无效")
		}
		id := (int(decoded[0]&0x7f)<<24 | int(decoded[1])<<16 | int(decoded[2])<<8 | int(decoded[3]))
		if id == 0 {
			id = 1
		}
		row["id"], row["port"], row["tag"] = id, port, "mxioc-inbound-"+strconv.Itoa(id)
		row["goCreateKey"], row["goCreateHash"] = key, requestHash
	}
	if tlsTemplate(template) {
		stream, err := inboundObject(row["streamSettings"])
		if err != nil {
			return nil, err
		}
		tls, err := inboundObject(stream["tlsSettings"])
		if err != nil {
			return nil, err
		}
		certs := anyRecords(tls["certificates"])
		if len(certs) != 1 {
			return nil, errors.New("独立内核 TLS 证书记录无效")
		}
		cert := Record{"certFile": certs[0]["certificateFile"], "keyFile": certs[0]["keyFile"], "serverName": tls["serverName"]}
		if err := verifyTemplateCertificate(ctx, run, cert); err != nil {
			return nil, err
		}
	}
	for _, item := range rows {
		existing := item.(Record)
		if value(existing["id"]) == value(row["id"]) || existing["tag"] == row["tag"] {
			return nil, errors.New("托管入站 ID 已存在")
		}
	}
	tag := value(row["tag"])
	deleted, err := inboundObject(stateDoc["goDeletedInbounds"])
	if err != nil {
		return nil, err
	}
	if _, exists := deleted[value(row["id"])]; exists {
		return nil, errors.New("该请求的入站 ID 已删除，请发起新的创建请求")
	}
	native, err := legacyNativeInbound(kind, row)
	if err != nil {
		return nil, err
	}
	next := maps.Clone(doc)
	if journal == nil || journal["after"] != before {
		for _, item := range live {
			if item.(Record)["tag"] == tag {
				return nil, errors.New("远端已有同名入站标签")
			}
		}
		if outbound != nil {
			next, err = patchCoreRelay(kind, doc, row, outbound)
			if err != nil {
				return nil, err
			}
		}
		next["inbounds"] = append(append([]any{}, live...), native)
	}
	stateDoc["inbounds"] = append(rows, row)
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	after := coreConfigHash(data)
	if journal == nil {
		journal = Record{"key": key, "operation": coreInboundCreate, "before": before, "after": after, "row": row}
		pending, err = m.SealUser(journal)
		if err != nil {
			return nil, err
		}
		if err := m.updateCoreUserState(server, stateToken, "", stateToken, pending); err != nil {
			return nil, err
		}
	} else if journal["after"] != after {
		return nil, errors.New("独立内核创建计划与保存记录不一致")
	}
	if _, err := applyCore(ctx, kind, raw, next, tag, run); err != nil {
		if (errors.Is(err, errCoreRolledBack) || errors.Is(err, errCoreValidation)) && journal["before"] == before {
			err = errors.Join(err, m.updateCoreUserState(server, stateToken, pending, stateToken, ""))
		}
		return nil, err
	}
	if err := m.updateCoreUserState(server, stateToken, pending, nextState, ""); err != nil {
		return nil, errors.New("远端入站已创建，总控保存待重试")
	}
	return Record{"inbound": row, "reused": false}, nil
}

func standaloneTemplateProtocol(kind, template string) string {
	switch template {
	case "vmess-tcp":
		return "vmess"
	case "trojan-tls":
		return "trojan"
	case "vless-ws-tls":
		return "vless"
	case "vless-reality":
		if kind == "xray" {
			return "vless"
		}
	case "hysteria2":
		if kind == "sing-box" {
			return "hysteria2"
		}
		if kind == "xray" {
			return "hysteria"
		}
	case "tuic":
		if kind == "sing-box" {
			return "tuic"
		}
	}
	return ""
}
