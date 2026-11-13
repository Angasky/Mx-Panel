package web

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/monitorhistory"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"math"
	"net/url"
	"sort"
	"time"
)

type probeCacheEntry struct {
	done  chan struct{}
	until time.Time
	data  json.RawMessage
	err   error
}

// Cache request bodies, not a second database of observations. Coalesce concurrent viewers.
func (s *Server) probeCached(ctx context.Context, cfg probeSyncConfig, path string, ttl time.Duration, out any) error {
	sum := sha256.Sum256([]byte(cfg.URL + "\x00" + cfg.Secret + "\x00" + path))
	key := hex.EncodeToString(sum[:])
	for {
		s.probeCacheMu.Lock()
		if s.probeCache == nil {
			s.probeCache = map[string]*probeCacheEntry{}
		}
		entry := s.probeCache[key]
		if entry != nil {
			select {
			case <-entry.done:
				if time.Now().Before(entry.until) {
					data, err := entry.data, entry.err
					s.probeCacheMu.Unlock()
					if err != nil {
						return err
					}
					return json.Unmarshal(data, out)
				}
			default:
				done := entry.done
				s.probeCacheMu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return ctx.Err()
				}
			}
		}
		for k, v := range s.probeCache {
			select {
			case <-v.done:
				if time.Now().After(v.until) {
					delete(s.probeCache, k)
				}
			default:
			}
		}
		if len(s.probeCache) >= 512 {
			s.probeCacheMu.Unlock()
			return errors.New("探针请求繁忙，请稍后刷新")
		}
		entry = &probeCacheEntry{done: make(chan struct{})}
		s.probeCache[key] = entry
		s.probeCacheMu.Unlock()
		var data json.RawMessage
		err := s.probeRequest(ctx, cfg, "GET", path, nil, &data)
		s.probeCacheMu.Lock()
		entry.data = data
		entry.err = err
		if err != nil {
			ttl = 5 * time.Second
		}
		entry.until = time.Now().Add(ttl)
		close(entry.done)
		s.probeCacheMu.Unlock()
		if err != nil {
			return err
		}
		return json.Unmarshal(data, out)
	}
}
func probeLinked(row remote.Record) bool {
	return stringField(row, "probeSource") != "" && stringField(row, "probeUUID") != ""
}
func (s *Server) probeConfigFor(row remote.Record) (probeSyncConfig, error) {
	cfg, e := s.readProbeSync()
	if e != nil || cfg.URL != stringField(row, "probeSource") || cfg.Secret == "" || !probeID.MatchString(stringField(row, "probeUUID")) {
		return cfg, errors.New("探针监控来源不可用，请检查同步设置；未回退 SSH 采样")
	}
	return cfg, nil
}

type probeReport struct {
	UUID    string    `json:"uuid"`
	Updated time.Time `json:"updated_at"`
	Uptime  int64     `json:"uptime"`
	CPU     struct {
		Name  string   `json:"name"`
		Cores int      `json:"cores"`
		Usage *float64 `json:"usage"`
	} `json:"cpu"`
	Ram struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"ram"`
	Swap struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"swap"`
	Disk struct {
		Total int64 `json:"total"`
		Used  int64 `json:"used"`
	} `json:"disk"`
	Network struct {
		Up        *float64 `json:"up"`
		Down      *float64 `json:"down"`
		TotalUp   *uint64  `json:"totalUp"`
		TotalDown *uint64  `json:"totalDown"`
	} `json:"network"`
	Load struct {
		Load1  *float64 `json:"load1"`
		Load5  *float64 `json:"load5"`
		Load15 *float64 `json:"load15"`
	} `json:"load"`
}

func metricValue(v *float64, max float64) *float64 {
	if v == nil || math.IsNaN(*v) || math.IsInf(*v, 0) || *v < 0 || *v > max {
		return nil
	}
	return v
}
func usagePercent(used, total int64) *float64 {
	if total <= 0 || used < 0 || used > total {
		return nil
	}
	v := float64(used) / float64(total) * 100
	return &v
}
func (s *Server) probeMetrics(ctx context.Context, row remote.Record) (remote.Record, error) {
	cfg, e := s.probeConfigFor(row)
	if e != nil {
		return nil, e
	}
	uuid := stringField(row, "probeUUID")
	var result struct {
		Data []probeReport `json:"data"`
	}
	if e = s.probeCached(ctx, cfg, "/api/recent/"+url.PathEscape(uuid), 10*time.Second, &result); e != nil {
		return nil, e
	}
	var latest *probeReport
	for i := range result.Data {
		v := &result.Data[i]
		if v.UUID != "" && v.UUID != uuid {
			return nil, errors.New("探针上报身份不匹配")
		}
		if v.Updated.IsZero() || v.Updated.After(s.now().Add(5*time.Second)) {
			continue
		}
		if latest == nil || v.Updated.After(latest.Updated) {
			latest = v
		}
	}
	if latest == nil {
		return nil, errors.New("探针暂无有效上报；未启动重复采样")
	}
	v := latest
	stale := s.now().Sub(v.Updated) > 90*time.Second
	var info probeClient
	var inventory []probeClient
	// Basic hardware metadata is cached much longer than resource values.
	if e = s.probeCached(ctx, cfg, "/api/admin/client/list", 5*time.Minute, &inventory); e == nil {
		for _, c := range inventory {
			if c.UUID == uuid {
				info = c
				break
			}
		}
	}
	cpuName := v.CPU.Name
	if cpuName == "" {
		cpuName = info.CPUName
	}
	cores := v.CPU.Cores
	if cores == 0 {
		cores = info.Cores
	}
	memory := remote.Record{"total": v.Ram.Total, "used": v.Ram.Used, "available": v.Ram.Total - v.Ram.Used, "percent": usagePercent(v.Ram.Used, v.Ram.Total), "swapTotal": v.Swap.Total, "swapUsed": v.Swap.Used}
	disks := []remote.Record{}
	if v.Disk.Total > 0 && v.Disk.Used >= 0 && v.Disk.Used <= v.Disk.Total {
		disks = append(disks, remote.Record{"mount": "探针汇总", "filesystem": "Komari", "total": v.Disk.Total, "used": v.Disk.Used, "available": v.Disk.Total - v.Disk.Used, "percent": usagePercent(v.Disk.Used, v.Disk.Total)})
	}
	view := remote.Record{"source": "komari", "sourceLabel": "Komari 探针（复用已有上报）", "serverId": row["id"], "managementIp": row["host"], "hostname": row["name"], "os": info.OS, "kernel": info.Kernel, "cpuModel": cpuName, "cores": cores, "sampledAt": float64(v.Updated.UnixMilli()) / 1000, "stale": stale, "warmingUp": false, "uptime": v.Uptime, "cpuPercent": metricValue(v.CPU.Usage, 100), "memory": memory, "load": []*float64{v.Load.Load1, v.Load.Load5, v.Load.Load15}, "interfaces": []remote.Record{}, "addresses": []remote.Record{}, "perCpu": []remote.Record{}, "summaryInterfaces": []string{"Komari 汇总"}, "disks": disks, "network": remote.Record{"rxBytes": v.Network.TotalDown, "txBytes": v.Network.TotalUp, "rxBytesPerSecond": metricValue(v.Network.Down, math.MaxFloat64), "txBytesPerSecond": metricValue(v.Network.Up, math.MaxFloat64)}}
	if stale {
		view["error"] = "原探针上报已超过 90 秒，显示最后数据；不会回退 SSH 采样"
	}
	return view, nil
}

type probeHistoryRecord struct {
	Client   string    `json:"client"`
	Time     time.Time `json:"time"`
	CPU      *float64  `json:"cpu"`
	Ram      int64     `json:"ram"`
	RamTotal int64     `json:"ram_total"`
	NetIn    *float64  `json:"net_in"`
	NetOut   *float64  `json:"net_out"`
}

func (s *Server) probeHistory(ctx context.Context, row remote.Record) (monitorhistory.State, error) {
	state := monitorhistory.State{Enabled: true, Points: []monitorhistory.Point{}, Days: []monitorhistory.Day{}}
	cfg, e := s.probeConfigFor(row)
	if e != nil {
		return state, e
	}
	uuid := stringField(row, "probeUUID")
	var result struct {
		Data struct {
			Records []probeHistoryRecord `json:"records"`
		} `json:"data"`
	}
	if e = s.probeCached(ctx, cfg, "/api/records/load?uuid="+url.QueryEscape(uuid)+"&hours=24&load_type=all", 60*time.Second, &result); e != nil {
		return state, e
	}
	points := map[int64]monitorhistory.Point{}
	for _, v := range result.Data.Records {
		if v.Client != "" && v.Client != uuid {
			return state, errors.New("探针历史身份不匹配")
		}
		if v.Time.Before(s.now().Add(-24*time.Hour)) || v.Time.After(s.now().Add(5*time.Second)) {
			continue
		}
		cpu := metricValue(v.CPU, 100)
		mem := usagePercent(v.Ram, v.RamTotal)
		rx := metricValue(v.NetIn, math.MaxFloat64)
		tx := metricValue(v.NetOut, math.MaxFloat64)
		points[v.Time.Unix()] = monitorhistory.Point{Time: v.Time.Unix(), OK: cpu != nil || mem != nil || rx != nil || tx != nil, CPU: cpu, Memory: mem, RXRate: rx, TXRate: tx}
	}
	for _, p := range points {
		state.Points = append(state.Points, p)
	}
	sort.Slice(state.Points, func(i, j int) bool { return state.Points[i].Time < state.Points[j].Time })
	if len(state.Points) > 2880 {
		sampled := make([]monitorhistory.Point, 0, 2880)
		for i := 0; i < 2880; i++ {
			sampled = append(sampled, state.Points[i*(len(state.Points)-1)/2879])
		}
		state.Points = sampled
	}
	return state, nil
}

// Shared monitoring also consumes upstream data without enabling a duplicate collector.
func (s *Server) monitorState(ctx context.Context, id string, history bool) (monitorhistory.State, error) {
	m, e := s.remoteManager()
	if e != nil {
		return monitorhistory.State{}, e
	}
	row, e := m.Record(id)
	if e != nil {
		return monitorhistory.State{}, e
	}
	if !probeLinked(row) {
		return s.history.Read(id, s.now())
	}
	if history {
		return s.probeHistory(ctx, row)
	}
	view, e := s.probeMetrics(ctx, row)
	if e != nil {
		return monitorhistory.State{Enabled: true}, e
	}
	p, _ := metricHistoryPoint(view, s.now())
	if !p.OK {
		if ts, ok := view["sampledAt"].(float64); ok {
			p.Time = int64(ts)
		}
	}
	return monitorhistory.State{Enabled: true, Points: []monitorhistory.Point{p}, Days: []monitorhistory.Day{}}, nil
}
