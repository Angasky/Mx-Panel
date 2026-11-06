package remote

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

//go:embed scripts/install-xray.sh
var installXray string

//go:embed scripts/install-sing-box.sh
var installSingBox string

func coreInstallScript(kind, config string) (string, error) {
	script := ""
	switch kind {
	case "xray":
		script = installXray
	case "sing-box":
		script = installSingBox
	default:
		return "", errors.New("当前安装适配仅支持独立 Xray / sing-box")
	}
	if len(config) > 128<<10 {
		return "", errors.New("安装配置超过 128 KB")
	}
	if config != "" {
		var doc Record
		if json.Unmarshal([]byte(config), &doc) != nil || doc == nil {
			return "", errors.New("安装配置必须为 JSON 对象")
		}
		for _, key := range []string{"inbounds", "outbounds"} {
			if _, ok := doc[key].([]any); !ok {
				return "", errors.New("安装配置缺少入站或出站数组")
			}
		}
	}
	return strings.ReplaceAll(strings.ReplaceAll(script, "\r\n", "\n"), "__MXIOC_CONFIG64__", base64.StdEncoding.EncodeToString([]byte(config))), nil
}

func (m *Manager) InstallJob(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("安装任务记录无效")
		}
		if job["id"] == id {
			return job, nil
		}
	}
	return nil, errors.New("安装任务不存在")
}

func (m *Manager) RecoverInstallJobs() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.installRecovered {
		return nil
	}
	data, err := m.load()
	if err != nil {
		return err
	}
	changed := false
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return errors.New("安装任务记录无效")
		}
		if job["status"] == "running" || job["status"] == "queued" {
			job["status"] = "interrupted"
			job["error"] = "总控已重启，远端执行结果待核对；未自动重放安装"
			job["finishedAt"] = time.Now().Unix()
			changed = true
		}
	}
	if changed {
		if err = m.flush(data); err != nil {
			return err
		}
	}
	m.installRecovered = true
	return nil
}

func (m *Manager) StartInstall(id string, confirmed bool) (Record, error) {
	if !confirmed {
		return nil, errors.New("请确认安装或更新服务器软件")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	record, err := find(data, id)
	if err != nil {
		return nil, err
	}
	if value(record["coreUserPending"]) != "" {
		return nil, errors.New("独立内核用户变更待核对，暂不能安装或更新")
	}
	if record["connectionMode"] != "install" {
		return nil, errors.New("已有软件接入模式不会执行安装脚本")
	}
	connection, err := m.connectionRecord(record)
	if err != nil {
		return nil, err
	}
	config := ""
	if value(record["coreConfig"]) != "" {
		config, err = m.Secret(record, "coreConfig")
		if err != nil {
			return nil, err
		}
	}
	script, err := coreInstallScript(value(record["installType"]), config)
	if record["installType"] == "3x-ui" {
		password, e := m.Secret(record, "panelPassword")
		if e != nil {
			return nil, e
		}
		script, err = panelInstallScript(record, password)
		redaction, _ := json.Marshal(Record{"password": password})
		config = string(redaction)
	}
	if err != nil {
		return nil, err
	}
	count := 0
	keep := []any{}
	active := []any{}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("安装任务记录无效")
		}
		if job["status"] == "running" || job["status"] == "queued" {
			count++
			if job["serverId"] == id {
				return nil, errors.New("服务器已有安装任务")
			}
			active = append(active, job)
		} else {
			keep = append(keep, job)
		}
	}
	if count >= 2 {
		return nil, errors.New("已有两个安装任务，请稍后再试")
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
		return nil, errors.New("服务器正在处理其他操作")
	}
	random := make([]byte, 12)
	if _, err = rand.Read(random); err != nil {
		<-gate
		return nil, err
	}
	jobID := hex.EncodeToString(random)
	job := Record{"id": jobID, "serverId": id, "installType": record["installType"], "status": "running", "startedAt": time.Now().Unix(), "log": "正在连接远端，详细日志将在任务结束后显示。", "error": ""}
	appendInstallStage(job, "connecting")
	if len(keep) > 47-len(active) {
		keep = keep[len(keep)-(47-len(active)):]
	}
	data["jobs"] = append(append(active, keep...), job)
	if err = m.flush(data); err != nil {
		<-gate
		return nil, err
	}
	parent := m.jobContext
	if parent == nil {
		parent = context.Background()
	}
	runner := m.installRun
	if runner == nil {
		runner = func(ctx context.Context, c Connection, script string) (string, error) {
			observer := &installStageWriter{report: func(stage string) { m.updateInstallStage(jobID, stage) }}
			output, e := executeObserved(ctx, c, script, 64<<10, observer)
			if e == nil && record["installType"] == "3x-ui" {
				m.updateInstallStage(jobID, "api-check")
				output += "\nMXIOC_STAGE=api-check\n"
				_, e = m.verifyInstalledPanel(ctx, id)
				if e != nil {
					output += "\n面板验证失败：" + e.Error() + "\n"
				}
			}
			return output, e
		}
	}
	result := Record{}
	for k, v := range job {
		result[k] = v
	}
	go m.runInstall(parent, connection, script, config, jobID, gate, runner)
	return result, nil
}
func (m *Manager) runInstall(parent context.Context, connection Connection, script, config, id string, gate chan struct{}, runner func(context.Context, Connection, string) (string, error)) {
	defer func() { <-gate }()
	ctx, cancel := context.WithTimeout(parent, 45*time.Minute)
	defer cancel()
	output, runErr := runner(ctx, connection, script)
	var doc any
	if json.Unmarshal([]byte(config), &doc) == nil {
		var scrub func(any)
		scrub = func(v any) {
			switch x := v.(type) {
			case map[string]any:
				for k, v := range x {
					switch strings.ToLower(k) {
					case "password", "auth", "privatekey", "private_key", "uuid", "id":
						if secret, ok := v.(string); ok && secret != "" {
							output = strings.ReplaceAll(output, secret, "[已隐藏]")
						}
					}
					scrub(v)
				}
			case []any:
				for _, v := range x {
					scrub(v)
				}
			}
		}
		scrub(doc)
	}
	for _, secret := range []string{connection.Password, config, base64.StdEncoding.EncodeToString([]byte(config))} {
		if secret != "" {
			output = strings.ReplaceAll(output, secret, "[已隐藏]")
		}
	}
	output = redactInstallLog(output)
	if len(output) > 64<<10 {
		output = output[len(output)-(64<<10):]
	}
	lastStage, installed := "", false
	for _, line := range strings.Split(output, "\n") {
		if stage := installStage(line); stage != "" {
			lastStage = stage
			installed = installed || stage == "installed"
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return
	}
	for _, v := range data["jobs"].([]any) {
		job := v.(map[string]any)
		if job["id"] != id {
			continue
		}
		job["log"] = output
		if server, e := find(data, value(job["serverId"])); e == nil && value(server["panelUrl"]) != "" {
			job["panelUrl"] = server["panelUrl"]
		}
		job["finishedAt"] = time.Now().Unix()
		if lastStage != "" && job["stage"] == "connecting" {
			appendInstallStage(job, lastStage)
		}
		if runErr == nil && installed {
			job["status"] = "succeeded"
			appendInstallStage(job, "complete")
		} else {
			job["status"] = "failed"
			var code remoteExitError
			if errors.As(runErr, &code) && code > 0 && code <= 255 {
				job["exitCode"] = int(code)
			}
			job["error"] = installFailure(value(job["stage"]), int(code))
			if ctx.Err() != nil {
				job["status"] = "interrupted"
				job["error"] = "安装超时或总控退出，远端状态待核对；未自动重放"
			}
			if strings.Contains(output, "MXIOC_ROLLBACK_FAILED") {
				job["error"] = value(job["error"]) + "；原安装恢复未确认，请核对服务器服务和配置"
			}
		}
	}
	_ = m.flush(data)
}
