package remote

import (
	"bytes"
	"context"
	"errors"
	"slices"
)

func (m *Manager) readStandaloneUser(ctx context.Context, id string, binding Record) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		saved, err := m.Secret(record, "coreState")
		if err != nil {
			return nil, err
		}
		state, err := parseLegacyCoreState(saved)
		if err != nil {
			return nil, err
		}
		return readCoreUser(ctx, kind, state, binding, run)
	})
}

func readCoreUser(ctx context.Context, kind string, state legacyCoreState, binding Record, run coreRunner) (Record, error) {
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	id := value(binding["inboundId"])
	tag := "mxioc-inbound-" + id
	var row, actual Record
	for _, candidate := range state.Inbounds {
		if value(candidate["id"]) == id {
			if row != nil || candidate["tag"] != tag {
				return nil, errors.New("独立内核绑定入站身份无效或重复")
			}
			row = candidate
		}
	}
	if row == nil || row["enable"] == false {
		return nil, errors.New("独立内核绑定入站缺失或停用")
	}
	for _, candidate := range anyRecords(doc["inbounds"]) {
		if candidate["tag"] == tag {
			if actual != nil {
				return nil, errors.New("独立内核存在重复入站标签")
			}
			actual = candidate
		}
	}
	expected, err := legacyNativeInbound(kind, row)
	if err != nil || actual == nil || !sameCoreInbound(expected, actual) {
		return nil, errors.New("独立内核远端入站与托管记录不一致")
	}
	user, err := FindUser(row, binding, false)
	if err != nil {
		return nil, err
	}
	result := Record{"inbound": row, "client": user}
	email := value(binding["userEmail"])
	groups, counts := coreCounterIndex(kind, doc, state.UserStats)
	if user["enable"] == false || counts[email] != 1 || !slices.Contains(groups[tag].emails, email) {
		result["counterError"] = "独立内核用户未启用计量或计数归属不唯一"
		return result, nil
	}
	counters, err := queryCoreCounters(ctx, kind, doc, state.UserStats, run)
	if err != nil {
		result["counterError"] = err.Error()
		return result, nil
	}
	current, _, err := readCore(ctx, kind, run)
	if err != nil || !bytes.Equal(raw, current) {
		result["counterError"] = "采集期间独立内核配置已变化或无法复核"
		return result, nil
	}
	count := counters[email]
	result["reading"] = Record{"source": "authenticated-client", "up": count.up, "down": count.down}
	return result, nil
}
