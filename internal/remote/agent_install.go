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

//go:embed scripts/install-agent-remote.sh
var agentInstallShell string

func agentInstallScript(config []byte) (string, error) {
	if len(config) > 64<<10 {
		return "", errors.New("Agent 配置超过 64 KiB")
	}
	var doc Record
	if json.Unmarshal(config, &doc) != nil || doc == nil {
		return "", errors.New("Agent 配置无效")
	}
	return strings.ReplaceAll(agentInstallShell, "__CONFIG64__", base64.StdEncoding.EncodeToString(config)), nil
}

// StartAgentInstall uses the same per-server operation gate and persistent job
// journal as core installation. Configuration and credentials never enter the journal.
func (m *Manager) StartAgentInstall(id string, config []byte, revision string) (Record, error) {
	script, e := agentInstallScript(config)
	if e != nil {
		return nil, e
	}
	return m.startAgentJob(id, script, revision, "v0.1.15")
}

//go:embed scripts/upgrade-agent-remote.sh
var agentUpgradeShell string

const AgentUpgradeVersion = "v0.1.35"

func (m *Manager) StartAgentUpgrade(id, revision string) (Record, error) {
	return m.startAgentJob(id, agentUpgradeShell, revision, AgentUpgradeVersion)
}
func (m *Manager) startAgentJob(id, script, revision, targetVersion string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return nil, e
	}
	record, e := find(data, id)
	if e != nil {
		return nil, e
	}
	if certificateRevision(record) != revision {
		return nil, errors.New("服务器身份已变化，请刷新后重试")
	}
	connection, e := m.connectionRecord(record)
	if e != nil {
		return nil, e
	}
	active, keep := []any{}, []any{}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("任务记录损坏")
		}
		if job["status"] == "running" || job["status"] == "queued" {
			if job["serverId"] == id {
				return nil, errors.New("该服务器已有安装任务")
			}
			active = append(active, job)
		} else {
			keep = append(keep, job)
		}
	}
	if len(active) >= 2 {
		return nil, errors.New("已有两个安装任务，请稍后重试")
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
	raw := make([]byte, 12)
	if _, e = rand.Read(raw); e != nil {
		<-gate
		return nil, e
	}
	jobID := hex.EncodeToString(raw)
	job := Record{"id": jobID, "serverId": id, "installType": "mxioc-agent", "agentVersion": targetVersion, "status": "running", "startedAt": time.Now().Unix(), "log": "正在通过已核对指纹的 SSH 部署 Agent。", "error": ""}
	appendInstallStage(job, "connecting")
	if len(keep) > 47-len(active) {
		keep = keep[len(keep)-(47-len(active)):]
	}
	data["jobs"] = append(append(active, keep...), job)
	if e = m.flush(data); e != nil {
		<-gate
		return nil, e
	}
	parent := m.jobContext
	if parent == nil {
		parent = context.Background()
	}
	runner := m.installRun
	if runner == nil {
		runner = func(ctx context.Context, c Connection, script string) (string, error) {
			return Execute(ctx, c, script, 16<<10)
		}
	}
	safeRunner := func(ctx context.Context, c Connection, script string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
		defer cancel()
		output, err := runner(ctx, c, script)
		if err == nil && strings.Contains(output, "\nMXIOC_AGENT_INSTALLED\n") {
			return "Agent 文件部署和服务启动检查通过；仍需核对面板连接状态。\nMXIOC_STAGE=installed\n", nil
		}
		log := "Agent 部署未确认成功；请检查远端网络、systemd 和配置。"
		if strings.Contains(output, "MXIOC_ROLLBACK_FAILED") {
			log += "\nMXIOC_ROLLBACK_FAILED"
		}
		if err == nil {
			err = errors.New("远端未确认 Agent 安装")
		}
		return log, err
	}
	result := Record{}
	for k, v := range job {
		result[k] = v
	}
	go m.runInstall(parent, connection, script, "", jobID, gate, safeRunner)
	return result, nil
}
