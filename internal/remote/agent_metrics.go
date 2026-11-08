package remote

import (
	"context"
	"crypto/sha256"
	"errors"
	"os/exec"
	"strings"
	"time"
)

// CollectAgentSample runs only the built-in read-only Linux resource script.
func CollectAgentSample(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = strings.NewReader(hostSampleScript)
	output := &capture{limit: 512 << 10}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Run(); err != nil {
		return "", errors.New("本机资源采样失败")
	}
	result, truncated := output.result()
	if truncated {
		return "", errors.New("采样超出大小限制")
	}
	return result, nil
}
func (m *Manager) AgentMetrics(ctx context.Context, id, registration, rawText string) (Record, error) {
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	if len(rawText) > 512<<10 {
		return nil, errors.New("采样超出大小限制")
	}
	raw, err := parseHostSample(rawText, time.Now())
	if err != nil {
		return nil, err
	}
	raw.view["serverId"] = id
	raw.view["name"] = record["name"]
	raw.view["managementIp"] = record["host"]
	epoch := sha256.Sum256([]byte("agent\x00" + id + "\x00" + registration + "\x00" + raw.boot))
	raw.view["counterEpoch"] = fmtHex(epoch)
	key := sha256.Sum256([]byte("agent\x00" + id + "\x00" + registration))
	m.mu.Lock()
	if m.monitor == nil {
		m.monitor = &hostMonitor{entries: map[[32]byte]*metricEntry{}}
	}
	monitor := m.monitor
	m.mu.Unlock()
	return monitor.sample(ctx, key, func(context.Context) (*hostSample, error) { return raw, nil })
}
func fmtHex(v [32]byte) string {
	const chars = "0123456789abcdef"
	b := make([]byte, 64)
	for i, c := range v {
		b[i*2] = chars[c>>4]
		b[i*2+1] = chars[c&15]
	}
	return string(b)
}
