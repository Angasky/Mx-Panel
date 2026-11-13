package web

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

type rolloutItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Revision string `json:"revision,omitempty"`
	Digest   string `json:"digest,omitempty"`
	Job      string `json:"job,omitempty"`
	Status   string `json:"status"`
	Finished int64  `json:"finished,omitempty"`
}
type agentRollout struct {
	TargetVersion string        `json:"targetVersion"`
	ID            string        `json:"id"`
	Owner         string        `json:"owner,omitempty"`
	Status        string        `json:"status"`
	Message       string        `json:"message"`
	Created       int64         `json:"created"`
	Updated       int64         `json:"updated"`
	Index         int           `json:"index"`
	Items         []rolloutItem `json:"items"`
}

func rolloutActive(status string) bool {
	return status == "queued" || status == "starting" || status == "running" || status == "waiting" || status == "canary"
}
func (s *Server) readRollout() (agentRollout, error) {
	var r agentRollout
	b, e := os.ReadFile(filepath.Join(s.options.Root, "agent-rollout.json"))
	if os.IsNotExist(e) {
		r.Status = "idle"
		return r, nil
	}
	if e != nil {
		return r, e
	}
	if len(b) > 64<<10 {
		return r, errors.New("升级批次过大")
	}
	if e = json.Unmarshal(b, &r); e != nil {
		return r, e
	}
	if len(r.Items) > 20 || r.Index < 0 || r.Index > len(r.Items) {
		return r, errors.New("升级批次损坏")
	}
	if r.Owner != s.rolloutOwner && rolloutActive(r.Status) {
		r.Status = "interrupted"
		r.Message = "面板已重启，批次不会自动继续；请检查已执行任务及 Agent 状态。"
		if e = s.writeRollout(r); e != nil {
			return r, e
		}
	}
	return r, nil
}
func (s *Server) writeRollout(r agentRollout) error {
	b, e := json.Marshal(r)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".agent-rollout-*")
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
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "agent-rollout.json"))
}

// Called while holding rolloutMu; blocks manual changes that could race the batch.
func (s *Server) rolloutContains(id string) bool {
	r, e := s.readRollout()
	if e != nil {
		return true
	}
	if !rolloutActive(r.Status) {
		return false
	}
	for _, item := range r.Items {
		if item.ID == id {
			return true
		}
	}
	return false
}
func (s *Server) agentRolloutRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/agent/rollout" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	if s.rolloutOwner == "" {
		s.rolloutOwner = rand.Text()
	}
	state, e := s.readRollout()
	if e != nil {
		problem(w, 500, "升级批次读取失败")
		return true
	}
	if r.Method == "POST" {
		var in struct {
			Action    string   `json:"action"`
			ID        string   `json:"id"`
			IDs       []string `json:"ids"`
			Confirmed bool     `json:"confirmed"`
		}
		if readJSON(w, r, &in) != nil || !in.Confirmed {
			problem(w, 400, "请确认升级操作")
			return true
		}
		switch in.Action {
		case "start":
			if rolloutActive(state.Status) {
				problem(w, 409, "已有升级批次，请先完成或停止")
				return true
			}
			if len(in.IDs) < 1 || len(in.IDs) > 20 {
				problem(w, 400, "请选择 1–20 台服务器")
				return true
			}
			manager, e := s.remoteManager()
			if e != nil {
				problem(w, 500, "服务器不可用")
				return true
			}
			s.agentMu.Lock()
			defer s.agentMu.Unlock()
			entries, e := s.readAgents()
			if e != nil {
				problem(w, 500, "Agent 信息不可用")
				return true
			}
			items := []rolloutItem{}
			seen := map[string]bool{}
			for _, id := range in.IDs {
				entry := entries[id]
				record, e := manager.Record(id)
				if seen[id] || e != nil || !entry.Enabled || entry.Mode == "pull" || entry.Revision != agentServerRevision(record) {
					problem(w, 400, "服务器重复、Agent 未启用、身份改变或为 Pull 模式；本批次仅支持主动上报模式")
					return true
				}
				seen[id] = true
				observation := s.agentViews[id]
				if observation.Digest != entry.Digest || observation.At.IsZero() || s.now().Sub(observation.At) > 90*time.Second || observation.At.After(s.now()) {
					problem(w, 409, "所选 Agent 必须有最近 90 秒有效上报，请先检查连接")
					return true
				}
				if entry.DeployJob != "" {
					if job, e := manager.InstallJob(entry.DeployJob); e == nil && (job["status"] == "running" || job["status"] == "queued") {
						problem(w, 409, "所选服务器已有任务")
						return true
					}
				}
				name, _ := record["name"].(string)
				items = append(items, rolloutItem{ID: id, Name: name, Revision: entry.Revision, Digest: entry.Digest, Status: "queued"})
			}
			state = agentRollout{TargetVersion: remote.AgentUpgradeVersion, ID: rand.Text(), Owner: s.rolloutOwner, Status: "queued", Message: "等待执行第一台；首台验证后需手动确认剩余批次。", Created: s.now().Unix(), Items: items}
		case "continue":
			if in.ID != state.ID || state.Status != "canary" {
				problem(w, 409, "批次已变化或不在首台验收阶段")
				return true
			}
			state.Status = "queued"
			state.Message = "首台已确认，继续逐台升级。"
		case "stop":
			if in.ID != state.ID || !rolloutActive(state.Status) {
				problem(w, 409, "批次已变化或已停止")
				return true
			}
			state.Status = "stopped"
			state.Message = "已停止后续派发；正在执行的远端任务不会被强杀，请检查其结果。"
		default:
			problem(w, 400, "批次操作无效")
			return true
		}
		state.Updated = s.now().Unix()
		if e = s.writeRollout(state); e != nil {
			problem(w, 500, "升级批次保存失败")
			return true
		}
	}
	state.Owner = ""
	for i := range state.Items {
		state.Items[i].Revision = ""
		state.Items[i].Digest = ""
	}
	respond(w, 200, state)
	return true
}
func rolloutObserve(r *agentRollout, status string, finished int64, observation agentObservation, now time.Time) {
	item := &r.Items[r.Index]
	if status == "failed" || status == "interrupted" {
		item.Status = status
		r.Status = "failed"
		r.Message = "当前服务器升级失败或执行结果未知，已停止后续派发。"
		return
	}
	if status != "succeeded" {
		return
	}
	if item.Finished == 0 {
		item.Finished = finished
		if item.Finished == 0 {
			item.Finished = now.Unix()
		}
	}
	item.Status = "waiting"
	r.Status = "waiting"
	r.Message = "远端进程检查通过，等待任务完成之后的新上报及目标版本确认。"
	if r.TargetVersion != "" && observation.Version == r.TargetVersion && observation.Digest == item.Digest && observation.At.Unix() > item.Finished && now.Sub(observation.At) <= 90*time.Second && !observation.At.After(now) {
		item.Status = "verified"
		r.Index++
		if r.Index == len(r.Items) {
			r.Status = "succeeded"
			r.Message = "全部服务器逐台完成程序检查、新上报及目标版本确认。"
		} else if r.Index == 1 {
			r.Status = "canary"
			r.Message = "首台已有目标版本的新上报，请验收后确认继续剩余服务器。"
		} else {
			r.Status = "queued"
			r.Message = "当前服务器验证通过，等待下一台。"
		}
	} else if now.Unix()-item.Finished >= 180 {
		item.Status = "unverified"
		r.Status = "failed"
		r.Message = "3 分钟内未收到任务完成后的目标版本有效上报，停止后续派发；请检查连接与运行版本。"
	}
}
func (s *Server) pollAgentRollout() {
	s.rolloutMu.Lock()
	defer s.rolloutMu.Unlock()
	state, e := s.readRollout()
	if e != nil || !rolloutActive(state.Status) || state.Status == "canary" || state.Index >= len(state.Items) {
		return
	}
	manager, e := s.remoteManager()
	if e != nil {
		return
	}
	s.agentMu.Lock()
	defer s.agentMu.Unlock()
	entries, e := s.readAgents()
	if e != nil {
		return
	}
	item := &state.Items[state.Index]
	entry := entries[item.ID]
	record, e := manager.Record(item.ID)
	if e != nil || !entry.Enabled || entry.Digest != item.Digest || entry.Revision != item.Revision || entry.Revision != agentServerRevision(record) {
		state.Status = "failed"
		state.Message = "服务器或 Agent 身份已变化，停止批次。"
		_ = s.writeRollout(state)
		return
	}
	if state.Status == "queued" {
		observation := s.agentViews[item.ID]
		if observation.Digest != item.Digest || observation.At.IsZero() || s.now().Sub(observation.At) > 90*time.Second || observation.At.After(s.now()) {
			state.Status = "failed"
			state.Message = "当前服务器上报已过期，未启动升级；请检查后重新创建批次。"
			_ = s.writeRollout(state)
			return
		}
		// Save intent before SSH; a crash in the gap becomes interrupted on restart.
		state.Status = "starting"
		item.Status = "starting"
		state.Updated = s.now().Unix()
		if s.writeRollout(state) != nil {
			return
		}
		job, err := manager.StartAgentUpgrade(item.ID, item.Revision)
		if err != nil {
			state.Status = "failed"
			state.Message = "无法启动升级任务，服务器可能已有其他操作；未继续批次。"
			item.Status = "failed"
		} else {
			item.Job = job["id"].(string)
			item.Status = "running"
			state.Status = "running"
			state.Message = "正在升级当前服务器，尚未派发下一台。"
			entry.DeployJob = item.Job
			entry.DeployHash = ""
			entries[item.ID] = entry
			if s.writeAgents(entries) != nil {
				state.Status = "failed"
				state.Message = "任务已启动但关联保存失败，请核对任务；停止后续派发。"
			}
		}
	} else {
		job, err := manager.InstallJob(item.Job)
		if err != nil {
			state.Status = "failed"
			state.Message = "任务记录不可用，请人工核对远端状态。"
		} else {
			raw, _ := json.Marshal(job)
			var j struct {
				Status   string `json:"status"`
				Finished int64  `json:"finishedAt"`
			}
			json.Unmarshal(raw, &j)
			rolloutObserve(&state, j.Status, j.Finished, s.agentViews[item.ID], s.now())
		}
	}
	state.Updated = s.now().Unix()
	_ = s.writeRollout(state)
}
