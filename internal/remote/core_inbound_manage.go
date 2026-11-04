package remote

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strconv"
	"strings"
)

const coreInboundDelete = "core-inbound-delete"

func (m *Manager) writeManagedCoreInbound(ctx context.Context, server string, id int, expected string, payload Record, editGuard func(Record, Record) error, deleteGuard func(Record) error) (Record, error) {
	return m.withCore(ctx, server, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.changeManagedCoreInbound(ctx, server, kind, record, id, expected, payload, editGuard, deleteGuard, run)
	})
}

func (m *Manager) changeManagedCoreInbound(ctx context.Context, server, kind string, record Record, id int, expected string, payload Record, editGuard func(Record, Record) error, deleteGuard func(Record) error, run coreRunner) (Record, error) {
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	if stateToken == "" || len(expected) != 64 {
		return nil, errors.New("请刷新列表后重新选择托管入站")
	}
	saved, err := m.Secret(record, "coreState")
	if err != nil {
		return nil, err
	}
	state, err := parseLegacyCoreState(saved)
	if err != nil {
		return nil, err
	}
	stateDoc, err := inboundObject(saved)
	if err != nil {
		return nil, err
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	inventory, err := coreInventory(kind, record, doc, saved)
	if err != nil {
		return nil, err
	}

	idText := strconv.Itoa(id)
	tag := "mxioc-inbound-" + idText
	deleted, err := inboundObject(stateDoc["goDeletedInbounds"])
	if err != nil {
		return nil, err
	}
	index := slices.IndexFunc(state.Inbounds, func(row Record) bool { return value(row["id"]) == idText })
	if index < 0 {
		if deleteGuard == nil || deleted[idText] != expected || containsConfigString(doc, tag) {
			return nil, errors.New("找不到匹配的托管入站，请刷新列表")
		}
		if err := deleteGuard(nil); err != nil {
			return nil, err
		}
		return Record{"deleted": true, "alreadyMissing": true}, nil
	}
	row := state.Inbounds[index]
	version, err := InboundVersion(row)
	if err != nil || version != expected {
		return nil, errors.New("托管入站已变化，请刷新列表")
	}
	status := anyRecords(inventory["inbounds"])[index]["coreStatus"]
	if deleteGuard == nil {
		name, ok := payload["remark"].(string)
		name = strings.TrimSpace(name)
		if !ok || len(payload) != 1 || name == "" || len([]rune(name)) > 100 {
			return nil, errors.New("请填写 1–100 字符的托管入站名称")
		}
		if pending != "" || (status != "present" && status != "disabled") {
			return nil, errors.New("托管入站配置尚未核对，暂不能修改")
		}
		next := maps.Clone(row)
		next["remark"] = name
		if err := editGuard(row, next); err != nil {
			return nil, err
		}
		state.Inbounds[index] = next
		stateDoc["inbounds"] = state.Inbounds
		sealed, err := m.SealUser(stateDoc)
		if err != nil {
			return nil, err
		}
		if err := m.updateCoreUserState(server, stateToken, "", sealed, ""); err != nil {
			return nil, err
		}
		return Record{"updated": true}, nil
	}

	if dependentInbound(record, id) {
		return nil, errors.New("该入站仍关联限速、计量或中转配置，请先清理关联资源")
	}
	before := coreConfigHash(raw)
	journal, _, err := m.coreUserJournal(pending, expected, coreInboundDelete, before)
	if err != nil {
		return nil, err
	}
	if journal == nil && status != "present" && status != "disabled" {
		return nil, errors.New("托管入站与远端配置不一致，未删除")
	}
	next := maps.Clone(doc)
	if rows, ok := doc["inbounds"].([]any); ok {
		next["inbounds"] = slices.DeleteFunc(slices.Clone(rows), func(item any) bool {
			return item.(Record)["tag"] == tag // coreInventory validated the list.
		})
	}
	if containsConfigString(next, tag) {
		return nil, errors.New("入站标签仍在内核配置中使用，请先移除引用")
	}
	stateDoc["inbounds"] = slices.Delete(state.Inbounds, index, index+1)
	deleted[idText] = expected
	stateDoc["goDeletedInbounds"] = deleted
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	data, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	after := coreConfigHash(data)
	if journal != nil && journal["after"] != after {
		return nil, errors.New("独立内核删除计划与保存记录不一致")
	}
	if err := deleteGuard(row); err != nil {
		return nil, err
	}
	if journal != nil || status == "present" {
		if journal == nil {
			journal = Record{"key": expected, "operation": coreInboundDelete, "before": before, "after": after, "inboundId": idText}
			pending, err = m.SealUser(journal)
			if err != nil {
				return nil, err
			}
			if err := m.updateCoreUserState(server, stateToken, "", stateToken, pending); err != nil {
				return nil, err
			}
		}
		if _, err := applyCore(ctx, kind, raw, next, tag, run); err != nil {
			return nil, err
		}
	}
	if err := m.updateCoreUserState(server, stateToken, pending, nextState, ""); err != nil {
		return nil, errors.New("远端入站已删除，总控保存待重试")
	}
	return Record{"deleted": true}, nil
}
