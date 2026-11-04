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
func planCoreUserChange(kind, operation string, state legacyCoreState, doc, binding Record, verifiedJournal bool, proposed ...Record) (Record, []Record, error) {
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
	user, err := FindUser(row, binding, operation == "remove" || operation == "add")
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
				case "add":
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
	if operation == "add" || operation == "resume" {
		if err := verifyCoreRelay(doc, row); err != nil {
			return nil, nil, err
		}
	}
	if operation == "add" {
		if !coreProvisionInbound(kind, row) {
			return nil, nil, errors.New("当前入站协议或认证配置不支持创建独立用户")
		}
		if row["enable"] == false {
			return nil, nil, errors.New("独立内核入站已停用")
		}
		if user == nil {
			if len(proposed) != 1 {
				return nil, nil, errors.New("缺少独立用户创建凭据")
			}
			clients, _ := settings["clients"].([]any)
			settings["clients"] = append(append([]any{}, clients...), proposed[0])
			nextRow["settings"] = settings
			if _, err := FindUser(nextRow, binding, false); err != nil {
				return nil, nil, err
			}
			user = proposed[0]
		} else if user["enable"] == false {
			return nil, nil, errors.New("已存在的独立用户已停用")
		}
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
			(!verifiedJournal && !sameCoreInbound(expected, actual)) {
			return nil, nil, errors.New("独立内核远端入站与托管记录不一致")
		}
		seen = true
		nextInbounds[i] = candidate
	}
	if !seen && row["enable"] != false {
		return nil, nil, errors.New("独立内核托管入站在远端缺失")
	}
	if user == nil && !verifiedJournal {
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
	return m.updateCoreUserStateLocked(id, expectedState, expectedPending, nextState, nextPending)
}

func (m *Manager) updateCoreUserStateLocked(id, expectedState, expectedPending, nextState, nextPending string) error {
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

func (m *Manager) changeStandaloneUser(ctx context.Context, id, operation string, binding, proposed Record) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.changeCoreUser(ctx, id, kind, operation, record, binding, run, proposed)
	})
}

func (m *Manager) changeCoreUser(ctx context.Context, id, kind, operation string, record, binding Record, run coreRunner, proposed ...Record) (Record, error) {
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
	before := coreConfigHash(raw)
	if operation == "add" && len(state.UserStats) == 0 {
		// Validate the requested binding against the actual inbound before
		// enabling statistics or restarting the remote service.
		_, _, err := planCoreUserChange(kind, operation, state, doc, binding, false, proposed...)
		if err != nil {
			return nil, err
		}
		if _, err := m.enableCoreStats(ctx, id, kind, record, run); err != nil {
			return nil, err
		}
		record, err = m.Record(id)
		if err != nil {
			return nil, err
		}
		saved, err = m.Secret(record, "coreState")
		if err != nil {
			return nil, err
		}
		state, err = parseLegacyCoreState(saved)
		if err != nil || len(state.UserStats) == 0 {
			return nil, errors.New("计量已启用，托管记录待重新核对")
		}
		raw, doc, err = readCore(ctx, kind, run)
		if err != nil {
			return nil, err
		}
		stateToken, pendingToken = value(record["coreState"]), value(record["coreUserPending"])
		before = coreConfigHash(raw)
	}
	journal, supersede, err := m.coreUserJournal(pendingToken, key, operation, before)
	if err != nil {
		return nil, err
	}
	next, rows, err := planCoreUserChange(kind, operation, state, doc, binding, journal != nil, proposed...)
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
	if operation == "add" {
		if _, err := queryCoreCounters(ctx, kind, doc, state.UserStats, run); err != nil {
			return nil, err
		}
		stats, err := extendCoreStats(kind, doc, next, state.UserStats, binding)
		if err != nil {
			return nil, err
		}
		stateDoc["userStats"] = stats
	}
	finish := func() (Record, error) {
		if operation != "add" {
			return Record{"updated": true, "removed": operation == "remove"}, nil
		}
		return readCoreUser(ctx, kind, legacyCoreState{Inbounds: rows, UserStats: stateDoc["userStats"].(Record)}, binding, run)
	}
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	if journal == nil && sameCoreInbound(next, doc) {
		if err := m.updateCoreUserState(id, stateToken, "", nextState, ""); err != nil {
			return nil, err
		}
		return finish()
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	after := coreConfigHash(payload)
	if journal == nil || supersede {
		previous := pendingToken
		// If the previous operation wrote to disk, rollback to this new
		// baseline can still leave legacy metadata out of sync.
		keepOnRollback := journal != nil && (journal["keepOnRollback"] == true || journal["before"] != before)
		journal = Record{"key": key, "operation": operation, "before": before, "after": after, "keepOnRollback": keepOnRollback, "inboundId": value(binding["inboundId"])}
		pendingToken, err = m.SealUser(journal)
		if err != nil {
			return nil, err
		}
		if err = m.updateCoreUserState(id, stateToken, previous, stateToken, pendingToken); err != nil {
			return nil, err
		}
	} else if journal["after"] != after {
		return nil, errors.New("独立内核待核对的配置与用户变更结果不一致")
	}
	tag := "mxioc-inbound-" + value(binding["inboundId"])
	if _, err := applyCore(ctx, kind, raw, next, tag, run); err != nil {
		if errors.Is(err, errCoreRolledBack) && journal["before"] == before && journal["keepOnRollback"] != true {
			err = errors.Join(err, m.updateCoreUserState(id, stateToken, pendingToken, stateToken, ""))
		}
		return nil, err
	}
	if err := m.updateCoreUserState(id, stateToken, pendingToken, nextState, ""); err != nil {
		return nil, errors.New("远端用户已变更，总控记录保存待重试")
	}
	return finish()
}

func coreUserChangeKey(binding Record) (string, error) {
	return identity(Record{"inboundId": value(binding["inboundId"]), "identityHash": binding["identityHash"],
		"userHash": binding["userHash"], "userEmail": binding["userEmail"]})
}

func (m *Manager) coreUserJournal(token, key, operation, currentHash string) (Record, bool, error) {
	if token == "" {
		return nil, false, nil
	}
	journal, err := m.OpenUser(token)
	if err != nil || journal["key"] != key ||
		(journal["before"] != currentHash && journal["after"] != currentHash) {
		return nil, false, errors.New("独立内核用户变更待核对，当前配置或绑定不匹配")
	}
	pending := value(journal["operation"])
	if pending == "" { // Older records only represented removal.
		pending = "remove"
	}
	if pending == operation {
		return journal, false, nil
	}
	// Revocation supersedes a quota transition for the same verified user.
	// A new pause may also supersede an unfinished resume, never vice versa.
	if (operation == "remove" && (pending == "pause" || pending == "resume" || pending == "add")) ||
		(operation == "pause" && pending == "resume") {
		return journal, true, nil
	}
	return nil, false, errors.New("独立内核已有待核对的用户操作，暂不能执行当前操作")
}
