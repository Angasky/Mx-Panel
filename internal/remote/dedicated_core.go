package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
)

func (m *Manager) dedicatedCore(ctx context.Context, server, kind string, record, binding Record, operation string, run coreRunner) (Record, error) {
	saved, err := m.Secret(record, "coreState")
	if err != nil {
		return nil, err
	}
	state, err := inboundObject(saved)
	if err != nil {
		return nil, err
	}
	id := value(binding["inboundId"])
	var row Record
	for _, candidate := range anyRecords(state["inbounds"]) {
		if value(candidate["id"]) == id {
			if row != nil {
				return nil, errors.New("专属入站重复")
			}
			row = candidate
		}
	}
	receipts, err := inboundObject(state["goDedicatedRemoved"])
	if err != nil {
		return nil, err
	}
	removed := false
	if row == nil {
		row, _ = receipts[id].(Record)
		removed = row != nil
		if !removed || operation != "remove" {
			return nil, errors.New("专属入站缺失")
		}
	}
	if _, err = DedicatedPasswordBinding(row, binding); err != nil {
		return nil, err
	}
	if coreRelayProof(row) != nil {
		return nil, errors.New("单密码专属入站仍有中转依赖，请先核对")
	}
	numberID, _ := strconv.Atoi(id)
	port, err := parsedPort(row["port"], 0)
	if err != nil || port == 0 {
		return nil, errors.New("专属端口无效")
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	key, err := identity([]any{"dedicated-inbound", binding["operationId"], binding["identityHash"], binding["dedicatedEndpointHash"]})
	if err != nil {
		return nil, err
	}
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	var intent Record
	before := coreConfigHash(raw)
	if pending != "" {
		intent, err = m.OpenUser(pending)
		if err != nil || intent["key"] != key || (intent["before"] != before && intent["after"] != before) {
			return nil, errors.New("专属入站操作待核对，配置或归属变化")
		}
		prior := value(intent["operation"])
		if operation == "read" && prior == "dedicated-pause" && binding["monthlyPaused"] == true {
			operation = "pause"
		}
		if prior != "dedicated-"+operation && !(operation == "remove" && (prior == "dedicated-pause" || prior == "dedicated-resume")) {
			return nil, errors.New("请先完成原专属入站操作")
		}
	}
	expected, err := legacyNativeInbound(kind, row)
	if err != nil {
		return nil, err
	}
	found := false
	kept := []any{}
	for _, candidate := range anyRecords(doc["inbounds"]) {
		if candidate["tag"] == row["tag"] {
			if found || !sameCoreInbound(expected, candidate) {
				return nil, errors.New("专属入站远端配置已变化")
			}
			found = true
			continue
		}
		if value(candidate["port"]) == strconv.Itoa(port) || value(candidate["listen_port"]) == strconv.Itoa(port) {
			return nil, errors.New("专属计量端口被其他入站共用")
		}
		kept = append(kept, candidate)
	}
	if intent == nil && found != (row["enable"] != false && !removed) {
		return nil, errors.New("专属入站运行状态与托管记录不一致")
	}
	if operation == "read" {
		if row["enable"] == false && binding["monthlyPaused"] != true {
			return nil, errors.New("入站被手动停用")
		}
		meters, err := inboundObject(record["meters"])
		if err != nil {
			return nil, err
		}
		if _, exists := meters[id]; !exists {
			if binding["status"] != "provisioning" {
				return nil, errors.New("专属计量登记缺失，不能自动重建计数")
			}
			if err = m.ensureDedicatedMeter(ctx, record, numberID, port, run); err != nil {
				return nil, err
			}
		} else {
			script, err := dedicatedMeterScript(meters, numberID, port)
			if err != nil {
				return nil, err
			}
			// Verification of existing rules does not reload systemd or replace rules.
			script = strings.Split(script, "chmod 600 \"$work/live\"")[0] + "printf 'MXIOC_DEDICATED_METER_READY\\n'\n"
			output, err := run(ctx, script, 8<<10)
			if err != nil || !strings.Contains(output, "MXIOC_DEDICATED_METER_READY") {
				return nil, errors.New("专属计量规则与登记不一致")
			}
		}
		reading, err := readDedicatedMeter(ctx, numberID, run)
		if err != nil {
			return nil, err
		}
		current, _, err := readCore(ctx, kind, run)
		if err != nil || !bytes.Equal(raw, current) {
			return nil, errors.New("采集期间专属入站配置变化")
		}
		return Record{"inbound": row, "client": Record{"enable": row["enable"]}, "reading": reading}, nil
	}
	if operation != "pause" && operation != "resume" && operation != "remove" {
		return nil, errors.New("专属内核操作无效")
	}
	if operation == "resume" && (binding["monthlyPaused"] != true || binding["monthlyBaselinePending"] == true) {
		return nil, errors.New("专属入站尚未满足自动恢复条件")
	}
	if !removed {
		next := maps.Clone(doc)
		next["inbounds"] = kept
		nextRow := maps.Clone(row)
		nextRow["enable"] = operation == "resume"
		if operation == "resume" {
			next["inbounds"] = append(kept, expected)
		}
		if operation == "remove" && containsConfigString(next, value(row["tag"])) {
			return nil, errors.New("专属入站仍被其他配置引用")
		}
		nextRows := []any{}
		for _, candidate := range anyRecords(state["inbounds"]) {
			if value(candidate["id"]) != id {
				nextRows = append(nextRows, candidate)
			} else if operation != "remove" {
				nextRows = append(nextRows, nextRow)
			}
		}
		state["inbounds"] = nextRows
		if operation == "remove" {
			receipts[id] = row
			state["goDedicatedRemoved"] = receipts
			deleted, err := inboundObject(state["goDeletedInbounds"])
			if err != nil {
				return nil, err
			}
			version, err := InboundVersion(row)
			if err != nil {
				return nil, err
			}
			deleted[id] = version
			state["goDeletedInbounds"] = deleted
		}
		nextState, err := m.SealUser(state)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		after := coreConfigHash(data)
		if intent != nil && intent["operation"] == "dedicated-"+operation {
			if intent["after"] != after {
				return nil, errors.New("专属入站恢复计划变化")
			}
			nextState = value(intent["nextState"])
		} else {
			intent = Record{"key": key, "operation": "dedicated-" + operation, "before": before, "after": after, "nextState": nextState}
			token, err := m.SealUser(intent)
			if err != nil {
				return nil, err
			}
			if err = m.updateCoreUserState(server, stateToken, pending, stateToken, token); err != nil {
				return nil, err
			}
			pending = token
		}
		if before != after {
			if _, err = applyCore(ctx, kind, raw, next, value(row["tag"]), run); err != nil {
				return nil, err
			}
		}
		if err = m.updateCoreUserState(server, stateToken, pending, nextState, ""); err != nil {
			return nil, err
		}
	}
	if operation == "remove" {
		record, err = m.Record(server)
		if err != nil {
			return nil, err
		}
		meters, err := inboundObject(record["meters"])
		if err != nil {
			return nil, err
		}
		if _, exists := meters[id]; exists {
			if err = m.clearLegacyMeter(ctx, record, numberID, port, run); err != nil {
				return nil, err
			}
		}
		record, err = m.Record(server)
		if err != nil {
			return nil, err
		}
		policies, err := inboundObject(record["bandwidths"])
		if err != nil {
			return nil, err
		}
		if _, exists := policies[id]; exists {
			if err = m.clearLegacyBandwidth(ctx, record, numberID, port, run); err != nil {
				return nil, err
			}
		}
		return Record{"removed": true}, nil
	}
	// A completed pause may need a subsequent read to establish a monthly
	// baseline. Return the confirmed enabled state; counters are sampled there.
	return Record{"updated": true, "client": Record{"enable": operation == "resume"}}, nil
}
