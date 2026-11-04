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
	path, err := corePath(kind)
	if err != nil {
		return nil, nil, err
	}
	output, err := run(ctx, "base64 < "+quote(path), 3<<20)
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

func applyCore(ctx context.Context, kind string, raw []byte, next Record, managedTag string, run coreRunner) (Record, error) {
	return applyCoreVerified(ctx, kind, raw, next, managedTag, "", run)
}

func applyCoreVerified(ctx context.Context, kind string, raw []byte, next Record, managedTag, verify string, run coreRunner) (Record, error) {
	script, err := coreWriteScript(kind, raw, next, managedTag, verify)
	if err != nil {
		return nil, err
	}
	output, err := run(ctx, script, 64<<10)
	if err != nil {
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
// removal and credential edits. Each call owns its SSH connection.
func (m *Manager) CoreConfig(ctx context.Context, id, expected string, next Record) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		if next != nil && value(record["coreUserPending"]) != "" {
			return nil, errors.New("独立内核用户变更待核对，暂不能修改配置")
		}
		return coreOperation(ctx, kind, expected, next, run)
	})
}

type coreRunner func(context.Context, string, int) (string, error)

func (m *Manager) withCore(ctx context.Context, id string, action func(context.Context, string, Record, coreRunner) (Record, error)) (Record, error) {
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
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
	if m.operations == nil {
		m.operations = map[string]chan struct{}{}
	}
	gate := m.operations[id]
	if gate == nil {
		gate = make(chan struct{}, 1)
		m.operations[id] = gate
	}
	select {
	case gate <- struct{}{}:
	default:
		m.mu.Unlock()
		return nil, errors.New("服务器正在处理其他操作")
	}
	m.mu.Unlock()
	defer func() { <-gate }()
	connection, err := m.connectionRecord(record)
	if err != nil {
		return nil, err
	}
	client, err := Connect(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-done:
		}
	}()
	return action(ctx, kind, record, func(ctx context.Context, script string, limit int) (string, error) {
		return executeClient(ctx, client, connection, script, limit)
	})
}
