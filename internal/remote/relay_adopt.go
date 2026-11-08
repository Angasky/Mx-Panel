package remote

import (
	"context"
	"errors"
	"strconv"
)

// Explicit adoption requires the administrator's original outbound and route,
// the current inbound version, and an existing legacy relay registry entry.
// Only hashes are retained; this does not modify the remote configuration.
func (m *Manager) AdoptLegacyRelay(ctx context.Context, server string, id int, expected string, evidence Record) (Record, error) {
	if id < 1 || len(expected) != 64 || evidence["confirmed"] != true {
		return nil, errors.New("请确认原始中转配置证据并刷新入站")
	}
	result, err := m.WithPanel(ctx, server, func(p *Panel, record Record) (any, error) {
		row, present, err := panelInbound(ctx, p, id)
		if err != nil {
			return nil, err
		}
		if !present {
			return nil, errors.New("中转入口不存在，无法核对")
		}
		live, _, err := readPanelConfig(ctx, p)
		if err != nil {
			return nil, err
		}
		proof, err := legacyRelayEvidence(record, row, live, id, expected, evidence)
		if err != nil {
			return nil, err
		}
		if err := m.recordRelay(server, row, value(proof["outboundTag"]), "active", proof); err != nil {
			return nil, err
		}
		return Record{"adopted": true, "remoteChanged": false}, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(Record), nil
}
func legacyRelayEvidence(record, row, live Record, id int, expected string, evidence Record) (Record, error) {
	version, err := InboundVersion(row)
	if err != nil || version != expected || value(row["id"]) != strconv.Itoa(id) {
		return nil, errors.New("中转入口已变化，请刷新核对")
	}
	entries, err := relayRecords(record)
	if err != nil {
		return nil, err
	}
	var legacy Record
	for _, entry := range entries {
		if value(entry["inboundId"]) == strconv.Itoa(id) {
			legacy = entry
		}
	}
	if legacy == nil || legacy["deletePending"] == true {
		return nil, errors.New("缺少旧中转登记或已有删除待核对")
	}
	outbound, ok := evidence["outbound"].(Record)
	if !ok {
		return nil, errors.New("请提供原备份中的出站对象")
	}
	route, ok := evidence["route"].(Record)
	if !ok {
		return nil, errors.New("请提供原备份中的路由对象")
	}
	tag := value(legacy["outboundTag"])
	if outbound["tag"] != tag || route["outboundTag"] != tag {
		return nil, errors.New("证据的出站标签与旧登记不一致")
	}
	proof, err := relayOwnership(Record{"outbounds": []any{outbound}, "routing": Record{"rules": []any{route}}}, tag, value(row["tag"]))
	if err != nil {
		return nil, err
	}
	proof["outboundTag"], proof["inboundId"] = tag, id
	// This also rejects shared routing, balancer references and nested detours.
	_, changed, err := stripOwnedRelay(live, proof)
	if err != nil {
		return nil, err
	}
	if !changed {
		return nil, errors.New("远端中转资源不存在，无法核对原配置")
	}
	// Require both resources, not merely one surviving resource.
	actual, err := relayOwnership(live, tag, value(row["tag"]))
	if err != nil || actual["outboundHash"] != proof["outboundHash"] || actual["routeHash"] != proof["routeHash"] {
		return nil, errors.New("原配置证据与远端中转不一致")
	}
	for _, key := range []string{"outboundHash", "routeHash", "inboundTag"} {
		if legacy[key] != nil && legacy[key] != proof[key] {
			return nil, errors.New("已有可信中转归属不能被替换")
		}
	}
	proof["ownershipSource"] = "administrator-original-config"
	return proof, nil
}
