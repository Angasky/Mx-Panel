package remote

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"strconv"
	"strings"
)

func coreCreateFencePath(key string) string { return "/var/lib/mxioc/create-canceled/" + key }
func coreCreateFenceScript(key string) string {
	return "set -Eeuo pipefail\nexec 9>/var/lock/mxioc-xui-install.lock\nflock -n 9 || exit 75\ninstall -d -m 700 /var/lib/mxioc/create-canceled\n: > " + quote(coreCreateFencePath(key)) + "\nsync -f " + quote(coreCreateFencePath(key)) + "\nprintf 'MXIOC_CREATE_FENCED\\n'\n"
}

// The local tombstone shares the reservation mutex; the remote tombstone shares
// the core writer's flock. A disconnected, delayed new writer cannot resurrect
// an inbound after cancellation has observed or removed it.
func (m *Manager) reserveCoreCancel(scope, key string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	journal, err := m.createJournal()
	if err != nil {
		return "", err
	}
	server, err := m.prepareCoreCancel(scope, key, journal)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(journal)
	if err != nil {
		return "", err
	}
	if err = write(filepath.Join(m.root, "inbound-creates.json"), raw); err != nil {
		return "", err
	}
	return server, nil
}

// Caller holds m.mu. This prepares the journal without writing it, so an
// entire batch can be validated and committed in one atomic file replacement.
func (m *Manager) prepareCoreCancel(scope, key string, journal Record) (string, error) {
	if entry, _ := journal[key].(Record); entry != nil {
		if entry["scope"] != scope {
			return "", errors.New("取消范围不匹配")
		}
		if entry["status"] == "canceled" {
			if entry["coreCleanupPending"] == true {
				return value(entry["serverId"]), nil
			}
			return "", nil
		}
		return "", errors.New("请求已在面板登记，请重试取消")
	}
	data, err := m.load()
	if err != nil {
		return "", err
	}
	server := ""
	serverRows, err := cancellationRecords(data["servers"])
	if err != nil {
		return "", err
	}
	for _, record := range serverRows {
		matched := false
		if token := value(record["coreUserPending"]); token != "" {
			intent, err := m.OpenUser(token)
			if err != nil {
				return "", err
			}
			matched = intent["key"] == key && (intent["operation"] == coreInboundCreate || intent["operation"] == "core-create-cancel")
		}
		if value(record["coreState"]) != "" {
			saved, err := m.Secret(record, "coreState")
			if err != nil {
				return "", err
			}
			state, err := parseLegacyCoreState(saved)
			if err != nil {
				return "", err
			}
			for _, row := range state.Inbounds {
				matched = matched || row["goCreateKey"] == key
			}
		}
		if matched {
			if server != "" {
				return "", errors.New("创建请求匹配多台服务器")
			}
			server = value(record["id"])
		}
	}
	if len(journal) >= 4096 {
		return "", errors.New("创建记录已达上限")
	}
	entry := Record{"scope": scope, "status": "canceled"}
	if server != "" {
		entry["serverId"], entry["coreCleanupPending"] = server, true
	}
	journal[key] = entry
	return server, nil
}
func (m *Manager) cancelPendingCoreCreate(ctx context.Context, scope, key, request string, guard func(string, string, int, Record) error) error {
	server, err := m.reserveCoreCancel(scope, key)
	if err != nil || server == "" {
		return err
	}
	_, err = m.withCore(ctx, server, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return nil, m.cancelCoreCreate(ctx, server, kind, key, request, record, run, guard)
	})
	if err != nil {
		return err
	}
	return m.finishCreateCancel(scope, key)
}
func (m *Manager) cancelCoreCreate(ctx context.Context, server, kind, key, request string, record Record, run coreRunner, guard func(string, string, int, Record) error) error {
	output, err := run(ctx, coreCreateFenceScript(key), 8<<10)
	if err != nil || !strings.Contains(output, "MXIOC_CREATE_FENCED") {
		return errors.New("远端创建仍在执行或取消屏障未确认，请重试取消")
	}
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	stateDoc := Record{"inbounds": []any{}}
	if stateToken != "" {
		saved, err := m.Secret(record, "coreState")
		if err != nil {
			return err
		}
		stateDoc, err = inboundObject(saved)
		if err != nil {
			return err
		}
	}
	stateRows, err := cancellationRecords(stateDoc["inbounds"])
	if err != nil {
		return err
	}
	var intent, row Record
	if pending != "" {
		intent, err = m.OpenUser(pending)
		if err != nil {
			return err
		}
		if intent["key"] != key || (intent["operation"] != coreInboundCreate && intent["operation"] != "core-create-cancel") {
			return errors.New("服务器还有其他待核对操作")
		}
		row, _ = intent["row"].(Record)
	}
	for _, candidate := range stateRows {
		if candidate["goCreateKey"] == key {
			if row != nil && value(row["id"]) != value(candidate["id"]) {
				return errors.New("创建归属重复")
			}
			row = candidate
		}
	}
	if receipts, ok := stateDoc["goCanceledCreates"].(Record); ok && receipts[key] == true && intent == nil {
		return nil
	}
	if row == nil || row["goCreateKey"] != key {
		return errors.New("取消请求缺少原入站凭据记录")
	}
	id, err := strconv.Atoi(value(row["id"]))
	if err != nil || id < 1 {
		return errors.New("取消入站 ID 无效")
	}
	if err = guard(request, server, id, row); err != nil {
		return err
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return err
	}
	before := coreConfigHash(raw)
	if intent != nil && intent["before"] != before && intent["after"] != before {
		return errors.New("远端配置已变化，取消清理等待核对")
	}
	if intent != nil && intent["operation"] == coreInboundCreate && intent["cancelFence"] != true && intent["before"] == before {
		return errors.New("旧创建请求没有远端取消屏障，须先确认迟到结果，取消意图已保留")
	}
	next := maps.Clone(doc)
	kept := []any{}
	found := false
	expected, err := legacyNativeInbound(kind, row)
	if err != nil {
		return err
	}
	nativeRows, err := cancellationRecords(doc["inbounds"])
	if err != nil {
		return err
	}
	for _, candidate := range nativeRows {
		if candidate["tag"] != row["tag"] {
			kept = append(kept, candidate)
			continue
		}
		if found || !sameCoreInbound(candidate, expected) {
			return errors.New("待取消远端入站身份变化")
		}
		found = true
	}
	if !found && intent == nil {
		return errors.New("已创建入站缺失且没有取消恢复记录")
	}
	next["inbounds"] = kept
	if proof := coreRelayProof(row); proof != nil {
		next, _, err = stripOwnedRelay(next, proof)
		if err != nil {
			return err
		}
	}
	if containsConfigString(next, value(row["tag"])) {
		return errors.New("待取消入站仍被其他配置引用")
	}
	rows := []any{}
	for _, candidate := range stateRows {
		if candidate["goCreateKey"] != key {
			rows = append(rows, candidate)
		}
	}
	stateDoc["inbounds"] = rows
	receipts, err := inboundObject(stateDoc["goCanceledCreates"])
	if err != nil {
		return err
	}
	receipts[key] = true
	stateDoc["goCanceledCreates"] = receipts
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return err
	}
	after := coreConfigHash(data)
	if intent != nil && intent["operation"] == "core-create-cancel" {
		if intent["after"] != after {
			return errors.New("取消计划变化")
		}
		nextState = value(intent["nextState"])
	} else {
		intent = Record{"key": key, "operation": "core-create-cancel", "before": before, "after": after, "row": row, "nextState": nextState}
		token, err := m.SealUser(intent)
		if err != nil {
			return err
		}
		if err = m.updateCoreUserState(server, stateToken, pending, stateToken, token); err != nil {
			return err
		}
		pending = token
	}
	if before != after {
		if _, err = applyCore(ctx, kind, raw, next, value(row["tag"]), run); err != nil {
			return err
		}
	}
	return m.updateCoreUserState(server, stateToken, pending, nextState, "")
}

// Never silently drop malformed records while generating a deletion config.
func cancellationRecords(raw any) ([]Record, error) {
	list, ok := raw.([]any)
	if !ok {
		return nil, errors.New("取消配置列表格式无效")
	}
	result := make([]Record, 0, len(list))
	for _, value := range list {
		row, ok := value.(map[string]any)
		if !ok || row == nil {
			return nil, errors.New("取消配置包含无效记录")
		}
		result = append(result, row)
	}
	return result, nil
}
