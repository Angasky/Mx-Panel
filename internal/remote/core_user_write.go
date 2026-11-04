package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
)

func coreConfigHash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Only the exact managed inbound and bound credential may be changed. Keep
// the legacy metadata until the restarted core confirms the new config.
func planCoreUserChange(kind, operation string, state legacyCoreState, doc, binding Record, recovering bool) (Record, []Record, error) {
	id := value(binding["inboundId"])
	tag := "mxioc-inbound-" + id
	rowIndex := -1
	for i, row := range state.Inbounds {
		if value(row["id"]) == id {
			if rowIndex >= 0 || row["tag"] != tag {
				return nil, nil, errors.New("独立内核托管入站身份无效或重复")
			}
			rowIndex = i
		}
	}
	if rowIndex < 0 {
		return nil, nil, errors.New("独立内核托管入站不存在")
	}
	row := state.Inbounds[rowIndex]
	user, err := FindUser(row, binding, operation == "remove")
	if err != nil {
		return nil, nil, err
	}
	expected, err := legacyNativeInbound(kind, row)
	if err != nil {
		return nil, nil, err
	}
	if operation == "resume" && (row["enable"] == false || binding["monthlyPaused"] != true || binding["monthlyBaselinePending"] == true) {
		return nil, nil, errors.New("独立内核用户尚不满足自动恢复条件")
	}
	nextRow := maps.Clone(row)
	settings, err := object(row["settings"])
	if err != nil {
		return nil, nil, err
	}
	settings = maps.Clone(settings)
	if user != nil {
		remaining := []any{}
		for _, candidate := range anyRecords(settings["clients"]) {
			if candidate["email"] == user["email"] {
				switch operation {
				case "remove":
					continue
				case "pause", "resume":
					candidate = maps.Clone(candidate)
					candidate["enable"] = operation == "resume"
				default:
					return nil, nil, errors.New("独立内核用户操作无效")
				}
			}
			remaining = append(remaining, candidate)
		}
		settings["clients"] = remaining
		nextRow["settings"] = settings
	}
	candidate, err := legacyNativeInbound(kind, nextRow)
	if err != nil {
		return nil, nil, err
	}
	var native []any
	if entries, exists := doc["inbounds"]; exists {
		var ok bool
		native, ok = entries.([]any)
		if !ok {
			return nil, nil, errors.New("独立内核入站列表格式无效")
		}
	}
	nextInbounds := append([]any{}, native...)
	seen := false
	for i, v := range native {
		actual, ok := v.(Record)
		if !ok {
			return nil, nil, errors.New("独立内核入站格式无效")
		}
		if actual["tag"] != tag {
			continue
		}
		if seen || row["enable"] == false ||
			(!sameCoreInbound(expected, actual) && !(recovering && sameCoreInbound(candidate, actual))) {
			return nil, nil, errors.New("独立内核远端入站与托管记录不一致")
		}
		seen = true
		nextInbounds[i] = candidate
	}
	if !seen && row["enable"] != false {
		return nil, nil, errors.New("独立内核托管入站在远端缺失")
	}
	if user == nil {
		return nil, nil, nil
	}
	next := maps.Clone(doc)
	if seen {
		next["inbounds"] = nextInbounds
	}
	rows := append([]Record(nil), state.Inbounds...)
	rows[rowIndex] = nextRow
	return next, rows, nil
}

func (m *Manager) updateCoreUserState(id, expectedState, expectedPending, nextState, nextPending string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	record, err := find(data, id)
	if err != nil {
		return err
	}
	if value(record["coreState"]) != expectedState || value(record["coreUserPending"]) != expectedPending {
		return errors.New("独立内核托管记录已变化")
	}
	record["coreState"] = nextState
	if nextPending == "" {
		delete(record, "coreUserPending")
	} else {
		record["coreUserPending"] = nextPending
	}
	return m.flush(data)
}

func (m *Manager) changeStandaloneUser(ctx context.Context, id, operation string, binding Record) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.changeCoreUser(ctx, id, kind, operation, record, binding, run)
	})
}

func (m *Manager) changeCoreUser(ctx context.Context, id, kind, operation string, record, binding Record, run coreRunner) (Record, error) {
	saved, err := m.Secret(record, "coreState")
	if err != nil {
		return nil, err
	}
	state, err := parseLegacyCoreState(saved)
	if err != nil {
		return nil, err
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	stateToken, pendingToken := value(record["coreState"]), value(record["coreUserPending"])
	key, err := coreUserChangeKey(binding)
	if err != nil {
		return nil, err
	}
	var journal Record
	if pendingToken != "" {
		journal, err = m.OpenUser(pendingToken)
		currentHash := coreConfigHash(raw)
		pendingOperation := value(journal["operation"])
		if pendingOperation == "" {
			pendingOperation = "remove"
		}
		if err != nil || pendingOperation != operation || journal["key"] != key || (journal["before"] != currentHash && journal["after"] != currentHash) {
			return nil, errors.New("独立内核有待核对的用户变更，当前配置或操作不匹配")
		}
	}
	next, rows, err := planCoreUserChange(kind, operation, state, doc, binding, journal != nil)
	if err != nil {
		return nil, err
	}
	if next == nil {
		if journal != nil {
			return nil, errors.New("独立内核待核对的用户记录不一致")
		}
		return Record{"updated": true, "removed": operation == "remove"}, nil
	}
	stateDoc, err := object(saved)
	if err != nil {
		return nil, err
	}
	stateDoc["inbounds"] = rows
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	if journal == nil && sameCoreInbound(next, doc) {
		if err := m.updateCoreUserState(id, stateToken, "", nextState, ""); err != nil {
			return nil, err
		}
		return Record{"updated": true, "removed": operation == "remove"}, nil
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	after := coreConfigHash(payload)
	before := coreConfigHash(raw)
	if journal == nil {
		pendingToken, err = m.SealUser(Record{"key": key, "operation": operation, "before": before, "after": after})
		if err != nil {
			return nil, err
		}
		if err = m.updateCoreUserState(id, stateToken, "", stateToken, pendingToken); err != nil {
			return nil, err
		}
	} else if journal["after"] != after {
		return nil, errors.New("独立内核待核对的配置与撤销结果不一致")
	}
	tag := "mxioc-inbound-" + value(binding["inboundId"])
	if _, err := applyCore(ctx, kind, raw, next, tag, run); err != nil {
		if errors.Is(err, errCoreRolledBack) && (journal == nil || journal["before"] == before) {
			err = errors.Join(err, m.updateCoreUserState(id, stateToken, pendingToken, stateToken, ""))
		}
		return nil, err
	}
	if err := m.updateCoreUserState(id, stateToken, pendingToken, nextState, ""); err != nil {
		return nil, errors.New("远端用户已变更，总控记录保存待重试")
	}
	return Record{"updated": true, "removed": operation == "remove"}, nil
}

func coreUserChangeKey(binding Record) (string, error) {
	return identity(Record{"inboundId": value(binding["inboundId"]), "identityHash": binding["identityHash"],
		"userHash": binding["userHash"], "userEmail": binding["userEmail"]})
}
