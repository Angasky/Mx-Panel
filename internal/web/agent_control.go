package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/agentcontrol"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type agentTask struct {
	Command agentcontrol.Command `json:"command"`
	Digest  string               `json:"digest"`
	Status  string               `json:"status"`
	Result  *agentcontrol.Result `json:"result,omitempty"`
}

func (s *Server) taskPath(id string) string {
	return filepath.Join(s.options.Root, "agent-task-"+id+".json")
}

// IDs come only from an existing server record, never an unchecked path component.
func (s *Server) readAgentTask(id string) (agentTask, error) {
	var task agentTask
	b, e := os.ReadFile(s.taskPath(id))
	if os.IsNotExist(e) {
		return task, nil
	}
	if e != nil {
		return task, e
	}
	var envelope struct {
		Sealed string `json:"sealed"`
	}
	if e = json.Unmarshal(b, &envelope); e != nil {
		return task, e
	}
	m, e := s.remoteManager()
	if e != nil {
		return task, e
	}
	opened, e := m.OpenUser(envelope.Sealed)
	if e != nil {
		return task, e
	}
	raw, e := json.Marshal(opened)
	if e != nil {
		return task, e
	}
	e = json.Unmarshal(raw, &task)
	return task, e
}
func (s *Server) writeAgentTask(id string, t agentTask) error {
	raw, e := json.Marshal(t)
	if e != nil {
		return e
	}
	var record map[string]any
	if e = json.Unmarshal(raw, &record); e != nil {
		return e
	}
	m, e := s.remoteManager()
	if e != nil {
		return e
	}
	sealed, e := m.SealUser(record)
	if e != nil {
		return e
	}
	b, e := json.Marshal(map[string]string{"sealed": sealed})
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".agent-task-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), s.taskPath(id))
}
func (s *Server) agentControlAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent/control" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	m, e := s.remoteManager()
	if e != nil {
		problem(w, 500, "服务器数据不可用")
		return true
	}
	if _, e = m.Record(id); e != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil {
		problem(w, 500, "Agent 配置读取失败")
		return true
	}
	entry := entries[id]
	record, recordErr := m.Record(id)
	if entry.Revision == "" || recordErr != nil || entry.Revision != agentServerRevision(record) {
		problem(w, 400, "请重新生成 Agent 配置以确认当前服务器身份")
		return true
	}
	if !entry.Enabled {
		problem(w, 400, "请先启用 Agent")
		return true
	}
	task, e := s.readAgentTask(id)
	if e != nil {
		problem(w, 500, "任务记录读取失败")
		return true
	}
	if task.Digest != entry.Digest {
		task = agentTask{}
	}
	if task.Status == "pending" && task.Command.Expires < s.now().Unix() {
		task.Status = "expired"
		task.Command.Content = ""
		if e = s.writeAgentTask(id, task); e != nil {
			problem(w, 500, "任务保存失败")
			return true
		}
	}
	if r.Method == "POST" {

		if task.Status == "pending" {
			problem(w, 409, "已有任务等待完成；超时后请先读取配置确认结果")
			return true
		}
		var command agentcontrol.Command
		if e = readJSON(w, r, &command); e != nil {
			problem(w, 400, "任务格式无效")
			return true
		}
		raw := make([]byte, 16)
		if _, e = rand.Read(raw); e != nil {
			problem(w, 500, "任务创建失败")
			return true
		}
		command.ID = hex.EncodeToString(raw)
		command.Expires = s.now().Add(3 * time.Minute).Unix()
		if e = agentcontrol.Validate(command); e != nil {
			problem(w, 400, e.Error())
			return true
		}
		view := s.agentViews[id]
		supported := false
		for _, target := range view.Capabilities {
			if target == command.Target {
				supported = true
			}
		}
		if view.Digest != entry.Digest || s.now().Sub(view.At) > 90*time.Second || !supported {
			problem(w, 400, "Agent 未连接或尚未在本机授权该服务")
			return true
		}
		task = agentTask{Command: command, Digest: entry.Digest, Status: "pending"}
		if e = s.writeAgentTask(id, task); e != nil {
			problem(w, 500, "任务保存失败")
			return true
		}
		if entry.Mode == "pull" {
			go s.dispatchAgentPull(id, entry, task.Command)
		}
	}
	respond(w, 200, map[string]any{"id": task.Command.ID, "status": task.Status, "target": task.Command.Target, "action": task.Command.Action, "expires": task.Command.Expires, "result": task.Result, "targets": s.agentViews[id].Capabilities})
	return true
}
func (s *Server) agentAcknowledgement(id, digest string, report agentcontrol.Report) agentcontrol.Ack {
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	ack := agentcontrol.Ack{OK: true}
	entries, e := s.readAgents()
	if e != nil || !entries[id].Enabled || entries[id].Digest != digest {
		return agentcontrol.Ack{}
	}
	m, recordErr := s.remoteManager()
	if recordErr != nil {
		return agentcontrol.Ack{}
	}
	record, recordErr := m.Record(id)
	if recordErr != nil {
		return agentcontrol.Ack{}
	}
	if entries[id].Revision != "" && entries[id].Revision != agentServerRevision(record) {
		return agentcontrol.Ack{}
	}
	view := s.agentViews[id]
	if report.Sample != "" {
		view.Capabilities = nil
	}
	if len(report.Capabilities) <= 16 {
		for _, name := range report.Capabilities {
			if len(name) <= 64 {
				view.Capabilities = append(view.Capabilities, name)
			}
		}
	}
	if report.Sample != "" {
		view.Probes = nil
		if len(report.Probes) <= 6 {
			seen := map[string]bool{}
			for _, p := range report.Probes {
				if p.Name == "" || !utf8.ValidString(p.Name) || strings.ContainsFunc(p.Name, unicode.IsControl) || len([]rune(p.Name)) > 40 || seen[p.Name] || p.Time > s.now().Unix()+5 || p.Time < s.now().Add(-2*time.Minute).Unix() {
					continue
				}
				seen[p.Name] = true
				if p.OK && (p.Milliseconds == nil || math.IsNaN(*p.Milliseconds) || math.IsInf(*p.Milliseconds, 0) || *p.Milliseconds < 0 || *p.Milliseconds > 3000) {
					continue
				}
				if !p.OK {
					p.Milliseconds = nil
				}
				view.Probes = append(view.Probes, p)
			}
		}
	}
	s.agentViews[id] = view
	task, e := s.readAgentTask(id)
	if e != nil || task.Digest != digest || task.Status != "pending" {
		return ack
	}
	if entries[id].Revision == "" {
		return ack
	}
	if task.Command.Expires < s.now().Unix() {
		task.Status = "expired"
		task.Command.Content = ""
		s.writeAgentTask(id, task)
		return ack
	}
	if report.Result != nil && report.Result.ID == task.Command.ID {
		result := *report.Result
		if len(result.Content) > agentcontrol.MaxConfig || len(result.Error) > 4096 || len(result.Revision) > 64 || len(result.State) > 32 {
			return agentcontrol.Ack{}
		}
		if task.Command.Action != "read" {
			result.Content = ""
		}
		task.Result = &result
		task.Status = "finished"
		task.Command.Content = ""
		if s.writeAgentTask(id, task) != nil {
			return agentcontrol.Ack{}
		}
		return ack
	}
	ack.Command = &task.Command
	return ack
}

func (s *Server) dispatchAgentPull(id string, entry agentRegistration, command agentcontrol.Command) {
	result := agentcontrol.Result{ID: command.ID, Error: "Pull 管理请求未确认结果，请重新读取配置和服务状态"}
	m, e := s.remoteManager()
	if e != nil {
		return
	}
	record, e := m.Record(id)
	if e != nil {
		return
	}
	if entry.Revision == "" || entry.Revision != agentServerRevision(record) {
		return
	}
	u, e := url.Parse(entry.URL)
	if e != nil || u.Scheme != "https" || u.User != nil || u.Path != "/metrics" || !strings.EqualFold(u.Hostname(), strings.Trim(stringField(record, "host"), "[]")) {
		return
	}
	u.Path = "/control"
	s.agentMu.Lock()
	entries, err := s.readAgents()
	valid := err == nil && entries[id].Enabled && entries[id].Digest == entry.Digest
	s.agentMu.Unlock()
	if !valid {
		return
	}
	secret, e := m.OpenUser(entry.Secret)
	if e != nil {
		return
	}
	// Keep the exact task ID on all transports; the Agent stores its receipt before side effects.
	client, transport := agentPullClient()
	defer transport.CloseIdleConnections()
	client.Timeout = 85 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 85*time.Second)
	defer cancel()
	raw, _ := json.Marshal(command)
	req, e := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(raw))
	if e != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+stringField(secret, "token"))
	req.Header.Set("Content-Type", "application/json")
	res, e := client.Do(req)
	if e == nil {
		defer res.Body.Close()
		var received agentcontrol.Result
		if res.StatusCode == 200 && json.NewDecoder(io.LimitReader(res.Body, 2<<20)).Decode(&received) == nil && received.ID == command.ID {
			result = received
		}
	}
	s.agentAcknowledgement(id, entry.Digest, agentcontrol.Report{Result: &result})
}
