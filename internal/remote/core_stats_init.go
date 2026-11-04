package remote

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strings"
)

const coreStatsListen = "127.0.0.1:10085"
const coreStatsInit = "stats-init"

func planCoreStats(kind string, doc Record) (Record, error) {
	next := maps.Clone(doc)
	switch kind {
	case "xray":
		if doc["api"] != nil || doc["stats"] != nil {
			return nil, errors.New("Xray 已有 API 或统计配置，请人工核对归属")
		}
		policy, err := coreConfigObject(doc, "policy")
		if err != nil {
			return nil, err
		}
		levels, err := coreConfigObject(policy, "levels")
		if err != nil {
			return nil, err
		}
		level, err := coreConfigObject(levels, "0")
		if err != nil {
			return nil, err
		}
		for _, key := range []string{"statsUserUplink", "statsUserDownlink"} {
			if setting, exists := level[key]; exists && setting != true {
				return nil, errors.New("Xray 已明确关闭默认级别用户计量，请人工核对策略")
			}
			level[key] = true
		}
		levels["0"], policy["levels"], next["policy"] = level, levels, policy
		next["stats"] = Record{}
		next["api"] = Record{"listen": coreStatsListen, "tag": "mxioc-user-stats", "services": []any{"StatsService"}}
	case "sing-box":
		experimental, err := coreConfigObject(doc, "experimental")
		if err != nil {
			return nil, err
		}
		if experimental["v2ray_api"] != nil {
			return nil, errors.New("sing-box 已有统计接口，请人工核对归属")
		}
		experimental["v2ray_api"] = Record{"listen": coreStatsListen, "stats": Record{"enabled": true, "users": []any{}}}
		next["experimental"] = experimental
	default:
		return nil, errors.New("服务器不是独立 Xray 或 sing-box")
	}
	return next, nil
}

func coreConfigObject(doc Record, key string) (Record, error) {
	if doc[key] == nil {
		return Record{}, nil
	}
	current, ok := doc[key].(Record)
	if !ok {
		return nil, errors.New("独立内核统计相关配置格式无效")
	}
	return maps.Clone(current), nil
}

func (m *Manager) EnableCoreStats(ctx context.Context, id string) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.enableCoreStats(ctx, id, kind, record, run)
	})
}

func (m *Manager) enableCoreStats(ctx context.Context, id, kind string, record Record, run coreRunner) (Record, error) {
	saved, err := m.Secret(record, "coreState")
	if err != nil {
		return nil, errors.New("该服务器没有旧版总控托管入站")
	}
	state, err := parseLegacyCoreState(saved)
	if err != nil || len(state.Inbounds) == 0 {
		return nil, errors.New("该服务器没有可核对的托管入站")
	}
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	before := coreConfigHash(raw)
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	journal, _, err := m.coreUserJournal(pending, coreStatsInit, coreStatsInit, before)
	if err != nil {
		return nil, err
	}
	if len(state.UserStats) != 0 {
		if journal != nil {
			return nil, errors.New("计量配置待核对，无法确认总控记录")
		}
		_, err = queryCoreCounters(ctx, kind, doc, state.UserStats, run)
		return Record{"enabled": err == nil}, err
	}
	stats := Record{"listen": coreStatsListen, "binary": "/usr/local/bin/xray", "users": []any{}}
	if err := checkCoreStatsTools(ctx, kind, run); err != nil {
		return nil, err
	}
	next := doc
	if journal == nil || journal["after"] != before {
		inventory, err := coreInventory(kind, record, doc, saved)
		if err != nil {
			return nil, err
		}
		verified := false
		for _, row := range anyRecords(inventory["inbounds"]) {
			if row["coreStatus"] == "present" {
				verified = true
				break
			}
		}
		if !verified {
			return nil, errors.New("没有与旧版记录一致的启用入站，暂不能配置计量")
		}
		if _, err := run(ctx, "command -v timeout >/dev/null && ! timeout 2 bash -c 'true </dev/tcp/127.0.0.1/10085' 2>/dev/null", 64<<10); err != nil {
			return nil, errors.New("统计端口已被占用，或服务器缺少 timeout 工具")
		}
		next, err = planCoreStats(kind, doc)
		if err != nil {
			return nil, err
		}
	}
	if _, err := coreStatsAddress(kind, next, stats); err != nil {
		return nil, err
	}
	stateDoc, err := object(saved)
	if err != nil {
		return nil, err
	}
	stateDoc["userStats"] = stats
	nextToken, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(next)
	if err != nil {
		return nil, err
	}
	after := coreConfigHash(payload)
	if journal == nil {
		journal = Record{"key": coreStatsInit, "operation": coreStatsInit, "before": before, "after": after}
		pending, err = m.SealUser(journal)
		if err != nil {
			return nil, err
		}
		if err := m.updateCoreUserState(id, stateToken, "", stateToken, pending); err != nil {
			return nil, err
		}
	} else if journal["after"] != after {
		return nil, errors.New("计量配置与已保存的写入计划不一致")
	}
	verify := "ready=0\nfor attempt in 1 2 3 4 5; do\n" +
		" if timeout 2 /usr/local/bin/xray api statsquery --server=127.0.0.1:10085 --pattern='user>>>' >/dev/null 2>&1; then ready=1; break; fi\n" +
		" sleep 1\ndone\ntest \"$ready\" = 1"
	if _, err := applyCoreVerified(ctx, kind, raw, next, "", verify, run); err != nil {
		if errors.Is(err, errCoreRolledBack) && journal["before"] == before {
			err = errors.Join(err, m.updateCoreUserState(id, stateToken, pending, stateToken, ""))
		}
		return nil, err
	}
	if _, err := queryCoreCounters(ctx, kind, next, stats, run); err != nil {
		return nil, err
	}
	if err := m.updateCoreUserState(id, stateToken, pending, nextToken, ""); err != nil {
		return nil, errors.New("远端计量已启用，总控记录保存待重试")
	}
	return Record{"enabled": true}, nil
}

func checkCoreStatsTools(ctx context.Context, kind string, run coreRunner) error {
	check := "test -x /usr/local/bin/xray"
	if kind == "sing-box" {
		check += " && /usr/bin/sing-box version"
	}
	output, err := run(ctx, check, 64<<10)
	if err != nil || (kind == "sing-box" && !strings.Contains(output, "with_v2ray_api")) {
		return errors.New("缺少 Xray 统计查询工具，或 sing-box 构建缺少 with_v2ray_api")
	}
	return nil
}
