package web

import (
	"context"
	"crypto/rand"
	"net/http"
)

type probeBatchItem struct {
	Checked int64  `json:"checked,omitempty"`
	UUID    string `json:"uuid"`
	Port    int    `json:"port"`
	Status  string `json:"status"`
	Error   string `json:"error,omitempty"`
	Started int64  `json:"started,omitempty"`
}
type probeBatch struct {
	ID      string           `json:"id"`
	Status  string           `json:"status"`
	Items   []probeBatchItem `json:"items"`
	Created int64            `json:"created"`
}

func (s *Server) probeBatchRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/probe-sync/batch" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.probeSyncMu.Lock()
	defer s.probeSyncMu.Unlock()
	cfg, e := s.readProbeSync()
	if e != nil {
		problem(w, 500, "同步配置读取失败")
		return true
	}
	if r.Method == "POST" {
		var in struct {
			Action    string           `json:"action"`
			ID        string           `json:"id"`
			Items     []probeBatchItem `json:"items"`
			Confirmed bool             `json:"confirmed"`
		}
		if readJSON(w, r, &in) != nil {
			return true
		}
		if !in.Confirmed {
			problem(w, 400, "请确认批量授权操作")
			return true
		}
		switch in.Action {
		case "start":
			if cfg.Batch != nil && cfg.Batch.Status == "running" {
				problem(w, 409, "已有批量接入正在执行")
				return true
			}
			if cfg.Secret == "" || len(in.Items) == 0 || len(in.Items) > 200 {
				problem(w, 400, "请先配置探针并选择 1–200 台服务器")
				return true
			}
			var clients []probeClient
			if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/client/list", nil, &clients); e != nil {
				problem(w, 400, e.Error())
				return true
			}
			known := map[string]bool{}
			for _, c := range clients {
				known[c.UUID] = true
			}
			seen := map[string]bool{}
			bound := map[string]bool{}
			for _, b := range cfg.Bindings {
				bound[b.UUID] = true
			}
			items := []probeBatchItem{}
			for _, item := range in.Items {
				if !probeID.MatchString(item.UUID) || !known[item.UUID] || seen[item.UUID] || bound[item.UUID] || item.Port < 1 || item.Port > 65535 {
					problem(w, 400, "选择包含重复、已接入、已有任务、未知服务器或无效端口")
					return true
				}
				seen[item.UUID] = true
				items = append(items, probeBatchItem{UUID: item.UUID, Port: item.Port, Status: "queued"})
			}
			if len(cfg.Bindings)+len(items) > 200 {
				problem(w, 400, "接入总数不能超过 200 台")
				return true
			}
			cfg.Batch = &probeBatch{ID: rand.Text(), Status: "running", Items: items, Created: s.now().Unix()}
		case "stop":
			if cfg.Batch == nil || cfg.Batch.ID != in.ID || cfg.Batch.Status != "running" {
				problem(w, 409, "批次已变化或已结束")
				return true
			}
			cfg.Batch.Status = "stopped"
		default:
			problem(w, 400, "操作无效")
			return true
		}
		if e = s.writeProbeSync(cfg); e != nil {
			problem(w, 500, "批次保存失败")
			return true
		}
	}
	respond(w, 200, map[string]any{"batch": cfg.Batch})
	return true
}

// Serialized with single-server actions. Dispatch intent is durable before sending;
// after a crash an ambiguous task is not repeated. Known pending tasks can be checked.
func (s *Server) pollProbeBatch(ctx context.Context) {
	s.probeSyncMu.Lock()
	defer s.probeSyncMu.Unlock()
	cfg, e := s.readProbeSync()
	if e != nil || cfg.Batch == nil || cfg.Batch.Status != "running" {
		return
	}
	batch := cfg.Batch
	active := 0
	queued := -1
	oldest := -1
	for i, item := range batch.Items {
		if item.Status == "queued" {
			if queued < 0 {
				queued = i
			}
		} else if item.Status == "starting" || item.Status == "waiting" {
			active++
			if oldest < 0 || item.Checked < batch.Items[oldest].Checked {
				oldest = i
			}
		}
	}
	chosen := oldest
	if active < 3 && queued >= 0 {
		chosen = queued
	}
	for i := range batch.Items {
		if i != chosen {
			continue
		}
		item := &batch.Items[i]
		item.Checked = s.now().Unix()
		if item.Status == "bound" || item.Status == "failed" || item.Status == "unknown" {
			continue
		}
		var binding *probeBinding
		for j := range cfg.Bindings {
			if cfg.Bindings[j].UUID == item.UUID {
				binding = &cfg.Bindings[j]
				break
			}
		}
		if binding != nil && binding.Status == "bound" {
			item.Status = "bound"
			item.Error = ""
			_ = s.writeProbeSync(cfg)
			return
		}
		if item.Status == "queued" {
			if binding != nil {
				item.Status = "failed"
				item.Error = "该服务器已有接入任务，请单独核对"
				_ = s.writeProbeSync(cfg)
				return
			}
			item.Status = "starting"
			item.Started = s.now().Unix()
			if s.writeProbeSync(cfg) != nil {
				return
			}
			e = s.probeSyncAction(ctx, &cfg, probeSyncInput{Action: "bind", UUID: item.UUID, Port: item.Port, Confirmed: true})
			if e != nil {
				item.Status = "failed"
				item.Error = e.Error()
			} else {
				item.Status = "waiting"
			}
		} else {
			if binding == nil || binding.Task == "" {
				item.Status = "unknown"
				item.Error = "派发结果未知，请在探针任务记录核对并恢复关联"
			} else {
				e = s.probeSyncAction(ctx, &cfg, probeSyncInput{Action: "check", UUID: item.UUID})
				for j := range cfg.Bindings {
					b := cfg.Bindings[j]
					if b.UUID == item.UUID {
						if b.Status == "bound" {
							item.Status = "bound"
							item.Error = ""
						} else if b.Status == "failed" {
							item.Status = "failed"
							item.Error = "原探针授权任务失败"
						}
					}
				}
				if e != nil {
					item.Error = e.Error()
				}
				if item.Status != "bound" && item.Status != "failed" && s.now().Unix()-item.Started >= 300 {
					item.Status = "failed"
					item.Error = "5 分钟内未完成验证，请单独核对接入结果；不会重复授权"
				}
			}
		}
		_ = s.writeProbeSync(cfg)
		return
	}
	if chosen >= 0 {
		return
	}
	batch.Status = "completed"
	for _, item := range batch.Items {
		if item.Status != "bound" {
			batch.Status = "partial"
			break
		}
	}
	_ = s.writeProbeSync(cfg)
}
