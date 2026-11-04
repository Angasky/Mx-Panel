package remote

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
)

// EditCoreInbound applies a scoped change to a tagged, manually managed
// inbound. The tag stays stable so routes keep pointing to the same entry.
func (m *Manager) EditCoreInbound(ctx context.Context, id, version, operation, tag string, inbound Record) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		if value(record["coreUserPending"]) != "" {
			return nil, errors.New("独立内核用户撤销待核对，暂不能修改配置")
		}
		return editCore(ctx, kind, version, run, func(doc Record) (Record, error) {
			return patchCoreInbound(doc, operation, tag, inbound)
		})
	})
}

func patchCoreInbound(doc Record, operation, tag string, inbound Record) (Record, error) {
	if tag == "" || strings.TrimSpace(tag) != tag || strings.HasPrefix(tag, "mxioc-inbound-") {
		return nil, errors.New("请填写有效的手工入站标签")
	}
	var rows []any
	if raw, exists := doc["inbounds"]; exists {
		var ok bool
		rows, ok = raw.([]any)
		if !ok {
			return nil, errors.New("内核入站列表格式无效")
		}
	}
	index := -1
	for i, item := range rows {
		row, ok := item.(map[string]any)
		if !ok {
			return nil, errors.New("内核入站格式无效")
		}
		if value(row["tag"]) == tag {
			if index >= 0 {
				return nil, errors.New("内核入站标签重复")
			}
			index = i
		}
	}
	switch operation {
	case "create", "update":
		if inbound == nil || value(inbound["tag"]) != tag {
			return nil, errors.New("入站配置必须保留指定的标签")
		}
		if operation == "create" {
			if index >= 0 {
				return nil, errors.New("入站标签已存在")
			}
			rows = append(rows, inbound)
		} else {
			if index < 0 {
				return nil, errors.New("入站不存在")
			}
			rows[index] = inbound
		}
	case "delete":
		if index < 0 {
			return nil, errors.New("入站不存在")
		}
		next := maps.Clone(doc)
		next["inbounds"] = slices.Delete(slices.Clone(rows), index, index+1)
		if containsConfigString(next, tag) {
			return nil, errors.New("入站标签仍在其他配置中使用，请先检查并移除引用")
		}
		return next, nil
	default:
		return nil, errors.New("不支持该入站操作")
	}
	doc["inbounds"] = rows
	return doc, nil
}
