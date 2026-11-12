package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/monitorhistory"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func (s *Server) monitorHistoryRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/history" {
		return false
	}
	if r.Method != "GET" && r.Method != "PUT" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	id := r.URL.Query().Get("id")
	manager, err := s.remoteManager()
	if err != nil {
		problem(w, 500, "服务器数据读取失败")
		return true
	}
	if _, err = manager.Record(id); err != nil {
		problem(w, 404, "服务器不存在")
		return true
	}
	switch r.Method {
	case "PUT":
		var input struct {
			Enabled *bool `json:"enabled"`
		}
		if readJSON(w, r, &input) != nil || input.Enabled == nil {
			problem(w, 400, "请指定是否启用历史采样")
			return true
		}
		err = s.history.Enable(id, *input.Enabled, s.now())
	case "DELETE":
		err = s.history.Clear(id)
	}
	if err != nil {
		problem(w, 500, "历史监控记录保存失败")
		return true
	}
	state, err := s.history.Read(id, s.now())
	if err != nil {
		problem(w, 500, "历史监控记录读取失败")
		return true
	}
	// Only aggregate resource observations leave storage; no credentials or counter identity.
	respond(w, 200, map[string]any{"enabled": state.Enabled, "points": state.Points, "days": state.Days, "interval": 30, "timezone": "UTC"})
	return true
}
func metricHistoryPoint(view remote.Record, now time.Time) (monitorhistory.Point, *monitorhistory.Counter) {
	p := monitorhistory.Point{Time: now.Unix()}
	raw, err := json.Marshal(view)
	if err != nil {
		return p, nil
	}
	var m struct {
		SampledAt float64  `json:"sampledAt"`
		Stale     bool     `json:"stale"`
		CPU       *float64 `json:"cpuPercent"`
		Memory    struct {
			Percent *float64 `json:"percent"`
		} `json:"memory"`
		Network struct {
			RX     *uint64  `json:"rxBytes"`
			TX     *uint64  `json:"txBytes"`
			RXRate *float64 `json:"rxBytesPerSecond"`
			TXRate *float64 `json:"txBytesPerSecond"`
		} `json:"network"`
		Interfaces []string `json:"summaryInterfaces"`
		Epoch      string   `json:"counterEpoch"`
	}
	if json.Unmarshal(raw, &m) != nil || m.Stale || m.SampledAt > float64(now.Unix())+1 || m.SampledAt < float64(now.Add(-60*time.Second).Unix()) {
		return p, nil
	}
	p = monitorhistory.Point{Time: int64(m.SampledAt), OK: true, CPU: m.CPU, Memory: m.Memory.Percent, RXRate: m.Network.RXRate, TXRate: m.Network.TXRate}
	if m.Network.RX == nil || m.Network.TX == nil || m.Epoch == "" || len(m.Interfaces) == 0 {
		return p, nil
	}
	sort.Strings(m.Interfaces)
	return p, &monitorhistory.Counter{Time: p.Time, Epoch: m.Epoch, Interfaces: strings.Join(m.Interfaces, ","), RX: *m.Network.RX, TX: *m.Network.TX}
}
func (s *Server) startMonitorHistory(ctx context.Context) {
	s.historyOnce.Do(func() {
		s.historyDone = make(chan struct{})
		externalDone := make(chan struct{})
		go func() {
			defer close(externalDone)
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.pollExternalTraffic(ctx)
				}
			}
		}()
		go func() {
			defer close(s.historyDone)
			defer func() { <-externalDone }()
			ticker := time.NewTicker(30 * time.Second)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					s.sampleMonitorHistory(ctx)
					s.pollNotifications(ctx)
				}
			}
		}()
	})
}
func (s *Server) sampleMonitorHistory(ctx context.Context) {
	manager, err := s.remoteManager()
	if err != nil {
		return
	}
	rows, err := manager.List()
	if err != nil {
		return
	}
	ids := []string{}
	for _, row := range rows {
		if id, ok := row["id"].(string); ok {
			ids = append(ids, id)
		}
	}
	if err = s.history.Prune(ids, s.now()); err != nil {
		log.Print("monitor history retention cleanup failed")
	}
	slots := make(chan struct{}, 3)
	var wg sync.WaitGroup
	for _, row := range rows {
		id, _ := row["id"].(string)
		state, e := s.history.Read(id, s.now())
		if e != nil {
			log.Printf("monitor history read failed")
			continue
		}
		if !state.Enabled {
			continue
		}
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case slots <- struct{}{}:
		}
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			defer func() { <-slots }()
			view, e := s.serverMetrics(ctx, id)
			if ctx.Err() != nil {
				return
			}
			s.recordProbes(id)
			now := s.now()
			point := monitorhistory.Point{Time: now.Unix()}
			var counter *monitorhistory.Counter
			if e == nil {
				point, counter = metricHistoryPoint(view, now)
			}
			if err := s.history.Record(id, point, counter, now); err != nil {
				sum := sha256.Sum256([]byte(id))
				log.Printf("monitor history write failed for %s", hex.EncodeToString(sum[:4]))
			}
		}(id)
	}
	wg.Wait()
}
