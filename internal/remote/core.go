package remote

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

func corePath(kind string) (string, error) {
	switch kind {
	case "xray":
		return "/usr/local/etc/xray/config.json", nil
	case "sing-box":
		return "/etc/sing-box/config.json", nil
	}
	return "", errors.New("请选择独立 Xray 或 sing-box 服务器")
}

func readCore(ctx context.Context, kind string, run func(context.Context, string, int) (string, error)) ([]byte, Record, error) {
	if kind == "sing-box" {
		if config, ok := ctx.Value(singConfigKey{}).(*singConfig); ok {
			return config.read(ctx, run)
		}
	}
	path, err := corePath(kind)
	if err != nil {
		return nil, nil, err
	}
	output, err := coreRPCExec(ctx, run, CoreRPCPlan{Action: "read"}, "base64 < "+quote(path), 3<<20)
	if err != nil {
		return nil, nil, errors.New("独立内核配置读取失败，请检查安装路径和权限")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(output), ""))
	if err != nil || len(raw) > 2<<20 || !json.Valid(raw) {
		return nil, nil, errors.New("独立内核配置不是有效 JSON 或超过 2 MB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var doc Record
	if decoder.Decode(&doc) != nil || doc == nil {
		return nil, nil, errors.New("独立内核配置必须为 JSON 对象")
	}
	return raw, doc, nil
}

func coreOperation(ctx context.Context, kind, expected string, next Record, run func(context.Context, string, int) (string, error)) (Record, error) {
	var edit func(Record) (Record, error)
	if next != nil {
		edit = func(Record) (Record, error) { return next, nil }
	}
	return editCore(ctx, kind, expected, run, edit)
}

func editCore(ctx context.Context, kind, expected string, run coreRunner, edit func(Record) (Record, error)) (Record, error) {
	raw, doc, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	version := hex.EncodeToString(sum[:])
	if edit == nil {
		return Record{"config": doc, "version": version, "kind": kind}, nil
	}
	if len(expected) != 64 || expected != version {
		return nil, errors.New("内核配置已变化，请重新读取后编辑")
	}
	next, err := edit(doc)
	if err != nil {
		return nil, err
	}
	return applyCore(ctx, kind, raw, next, "", run)
}

var errCoreRolledBack = errors.New("内核应用失败，原配置和服务已恢复")
var errCoreValidation = errors.New("内核拒绝了候选配置，远端配置未修改")

func applyCore(ctx context.Context, kind string, raw []byte, next Record, managedTag string, run coreRunner) (Record, error) {
	return applyCoreVerified(ctx, kind, raw, next, managedTag, "", run)
}

func applyCoreVerified(ctx context.Context, kind string, raw []byte, next Record, managedTag, verify string, run coreRunner, cancelKey ...string) (Record, error) {
	script, err := coreWriteScript(kind, raw, next, managedTag, verify, cancelKey...)
	if err == nil && kind == "sing-box" {
		if config, ok := ctx.Value(singConfigKey{}).(*singConfig); ok {
			script, err = config.writeScript(raw, next, managedTag, verify, cancelKey...)
		}
	}
	if err != nil {
		return nil, err
	}
	if _, ok := ctx.Value(coreRPCKey{}).(CoreRPC); ok && verify != "" && verify != xrayStatsReady {
		return nil, errors.New("此验证流程暂不支持 Agent API")
	}
	output, err := coreRPCExec(ctx, run, CoreRPCPlan{Action: "apply", Previous: raw, Next: next, Tag: managedTag, StatsReady: verify == xrayStatsReady, CancelKeys: cancelKey}, script, 64<<10)
	if err != nil {
		if strings.Contains(output, "MXIOC_CORE_VALIDATION_FAILED") {
			return nil, errCoreValidation
		}
		if strings.Contains(output, "MXIOC_CORE_ROLLBACK_FAILED") {
			return nil, errors.New("内核应用失败且回滚未确认，请检查服务器服务状态")
		}
		if strings.Contains(output, "MXIOC_CORE_ROLLED_BACK") {
			return nil, errCoreRolledBack
		}
		return nil, errors.New("内核写入结果待核对，请重新读取；未自动重放请求")
	}
	if !strings.Contains(output, "MXIOC_CORE_APPLIED") {
		return nil, errors.New("内核应用结果未确认，请重新读取")
	}
	// Single-file writers attest the actual bytes on disk while still holding
	// the remote lock. Avoid another SSH channel and a full configuration download.
	// Multi-file sing-box writers retain their layout-aware readback below.
	const savedPrefix = "MXIOC_CORE_SAVED_SHA256="
	if strings.Contains(output, savedPrefix) {
		want, err := json.Marshal(next)
		if err != nil {
			return nil, errors.New("内核保存结果无法校验，请重新读取")
		}
		expected := coreConfigHash(want)
		count := 0
		for _, line := range strings.Split(output, "\n") {
			if strings.HasPrefix(line, savedPrefix) {
				count++
				if strings.TrimPrefix(line, savedPrefix) != expected {
					return nil, errors.New("内核保存结果与请求不同，请重新读取核对")
				}
			}
		}
		if count != 1 {
			return nil, errors.New("内核保存校验结果无效，请重新读取核对")
		}
		return Record{"updated": true, "version": expected, "kind": kind}, nil
	}
	after, actual, err := readCore(ctx, kind, run)
	if err != nil {
		return nil, errors.New("内核请求已执行，保存结果读取待核对")
	}
	want, _ := json.Marshal(next)
	got, _ := json.Marshal(actual)
	if string(want) != string(got) {
		return nil, errors.New("内核保存结果与请求不同，请重新读取核对")
	}
	sum := sha256.Sum256(after)
	return Record{"updated": true, "version": hex.EncodeToString(sum[:]), "kind": kind}, nil
}

// CoreConfig uses the same per-server exclusion gate as panel writes, server
// removal and credential edits. Each call exclusively leases its SSH transport.
func (m *Manager) CoreConfig(ctx context.Context, id, expected string, next Record) (Record, error) {
	if next == nil {
		ctx = context.WithValue(ctx, inventoryWaitKey{}, true)
	}
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		if next != nil && value(record["coreUserPending"]) != "" {
			return nil, errors.New("独立内核用户变更待核对，暂不能修改配置")
		}
		if next != nil && value(record["coreState"]) != "" {
			saved, err := m.Secret(record, "coreState")
			if err != nil {
				return nil, err
			}
			state, err := parseLegacyCoreState(saved)
			if err != nil {
				return nil, err
			}
			for _, row := range state.Inbounds {
				if err := verifyCoreRelay(next, row); err != nil {
					return nil, err
				}
			}
		}
		return coreOperation(ctx, kind, expected, next, run)
	})
}

type coreRunner func(context.Context, string, int) (string, error)

func (m *Manager) withCore(ctx context.Context, id string, action func(context.Context, string, Record, coreRunner) (Record, error), detectSing ...bool) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	gate, err := m.coreGate(ctx, id)
	if err != nil {
		return nil, err
	}
	defer func() { <-gate }()
	if ctx.Value(inventoryWaitKey{}) != true {
		defer m.invalidateInventoryView(id)
	}
	m.mu.Lock()
	data, err := m.load()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	record, err := find(data, id)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	kind := value(record["installType"])
	if len(detectSing) > 0 && detectSing[0] {
		if kind != "sing-box" && !probeInventoryOnly(record) {
			m.mu.Unlock()
			return nil, errors.New("此服务器已接管其他内核，请勿自动更换类型")
		}
		kind = "sing-box"
	}
	if _, err = corePath(kind); err != nil {
		m.mu.Unlock()
		return nil, err
	}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			m.mu.Unlock()
			return nil, errors.New("服务器任务记录无效")
		}
		if job["serverId"] == id && (job["status"] == "running" || job["status"] == "queued") {
			m.mu.Unlock()
			return nil, errors.New("请等待服务器任务完成")
		}
	}
	m.mu.Unlock()
	m.mu.Lock()
	resolver := m.coreRPCResolver
	m.mu.Unlock()
	if kind == "xray" && resolver != nil {
		if rpc := chosenCoreRPC(ctx, id, record, resolver); rpc != nil {
			ctx = context.WithValue(ctx, coreRPCKey{}, rpc)
			blocked := coreRunner(func(context.Context, string, int) (string, error) {
				return "", errors.New("此操作尚未适配 Agent 节点 API，未自动回退或重放")
			})
			result, err := action(ctx, kind, record, blocked)
			if result != nil {
				result["managementTransport"] = "agent-api"
			}
			return result, err
		}
	}
	connection, err := m.connectionRecord(record)
	if err != nil {
		return nil, err
	}
	client, err := m.takeCoreSession(ctx, id, connection)
	if err != nil {
		return nil, err
	}
	ctx = context.WithValue(ctx, coreStatsQueryKey{}, coreStatsQuery(func(ctx context.Context, address string) (string, error) {
		return querySingStats(ctx, address, client.DialContext)
	}))
	done := make(chan struct{})
	watchDone := make(chan struct{})
	healthy := false
	transportHealthy := true
	defer func() {
		close(done)
		<-watchDone
		if healthy && transportHealthy && ctx.Err() == nil {
			m.keepCoreSession(id, connection, client)
		} else {
			client.Close()
		}
	}()
	go func() {
		defer close(watchDone)
		select {
		case <-ctx.Done():
			client.Close()
		case <-done:
		}
	}()
	run := coreRunner(func(ctx context.Context, script string, limit int) (string, error) {
		output, err := executeClient(ctx, client, connection, script, limit)
		if err != nil {
			transportHealthy = false
		}
		return output, err
	})
	if kind == "sing-box" {
		config, e := newSingConfig(ctx, run)
		if e != nil {
			return nil, e
		}
		ctx = context.WithValue(ctx, singConfigKey{}, config)
	}
	result, err := action(ctx, kind, record, run)
	healthy = err == nil
	return result, err
}
