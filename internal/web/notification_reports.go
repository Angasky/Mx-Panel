package web

import (
	"crypto/sha256"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
)

// Five-minute windows, at least five measurements, and a fresh final observation.
// ICMP samples that could not be sent must never be counted as packet loss.
func notificationProbeConditions(id, name string, points []netprobe.Result, c notificationConfig, now time.Time) map[string]string {
	out := map[string]string{}
	groups := map[string][]netprobe.Result{}
	for _, p := range points {
		if p.Method == "" {
			p.Method = "tcp"
		}
		if p.Method != "tcp" && p.Method != "icmp" {
			continue
		}
		if p.Time > now.Unix() {
			continue
		}
		key := fmt.Sprintf("%x", sha256.Sum256([]byte(id+"\x00"+p.Method+"\x00"+p.Name)))
		groups[key] = append(groups[key], p)
	}
	for key, rows := range groups {
		sort.Slice(rows, func(i, j int) bool { return rows[i].Time < rows[j].Time })
		last := rows[len(rows)-1]
		lossKey, latencyKey := "probe-loss:"+key, "probe-latency:"+key
		out["unknown:"+lossKey] = "1"
		out["unknown:"+latencyKey] = "1"
		if last.Time < now.Add(-120*time.Second).Unix() || (last.Method == "icmp" && !last.Sent) {
			continue
		}
		attempts, failed, measured := 0, 0, 0
		sum := float64(0)
		var seen int64 = -1
		for _, p := range rows {
			if p.Time < now.Add(-5*time.Minute).Unix() || p.Time == seen {
				continue
			}
			seen = p.Time
			if p.Method == "icmp" && !p.Sent {
				continue
			}
			attempts++
			if !p.OK {
				failed++
			}
			if p.OK && p.Milliseconds != nil && *p.Milliseconds >= 0 && !math.IsNaN(*p.Milliseconds) && !math.IsInf(*p.Milliseconds, 0) {
				sum += *p.Milliseconds
				measured++
			}
		}
		if attempts >= 5 {
			delete(out, "unknown:"+lossKey)
			label := "TCP 连接失败比例"
			if last.Method == "icmp" {
				label = "ICMP 已发送样本丢包比例"
			}
			if float64(failed)*100/float64(attempts) >= float64(c.LossPercent) {
				out[lossKey] = fmt.Sprintf("服务器「%s」探测「%s」近 5 分钟%s达到 %d%% 阈值。", name, last.Name, label, c.LossPercent)
			} else {
				out["healthy:"+lossKey] = "1"
			}
		}
		if measured >= 5 {
			delete(out, "unknown:"+latencyKey)
			if sum/float64(measured) >= float64(c.LatencyMS) {
				out[latencyKey] = fmt.Sprintf("服务器「%s」探测「%s」（%s）近 5 分钟成功样本平均延迟达到 %d 毫秒阈值。", name, last.Name, last.Method, c.LatencyMS)
			} else {
				out["healthy:"+latencyKey] = "1"
			}
		}
	}
	return out
}

// Previous UTC calendar day: network observations, not a subscription billing delta.
func (s *Server) notificationDailyReport(now time.Time) (string, error) {
	date := now.UTC().AddDate(0, 0, -1).Format("2006-01-02")
	manager, e := s.remoteManager()
	if e != nil {
		return "", e
	}
	rows, e := manager.List()
	if e != nil {
		return "", e
	}
	enabled, observed := 0, 0
	rx, tx, seconds := float64(0), float64(0), float64(0)
	gaps := 0
	for _, r := range rows {
		if probeLinked(r) {
			continue
		}
		id, _ := r["id"].(string)
		h, e := s.history.Read(id, now)
		if e != nil {
			return "", e
		}
		if h.Enabled {
			enabled++
		}
		for _, d := range h.Days {
			if d.Date == date {
				rx += float64(d.RX)
				tx += float64(d.TX)
				seconds += float64(d.Seconds)
				gaps += d.Gaps
				if d.Seconds > 0 {
					observed++
				}
			}
		}
	}
	profiles, e := s.repository.Profiles()
	if e != nil {
		return "", e
	}
	configured, exhausted, expired := 0, 0, 0
	for _, p := range profiles {
		id, _ := p["id"].(string)
		state, e := s.repository.State(id)
		if e != nil {
			return "", e
		}
		info, e := config.TrafficInfo(state, now)
		if e != nil {
			return "", e
		}
		if info["configured"] != true {
			continue
		}
		configured++
		if info["exhausted"] == true {
			exhausted++
		}
		if info["expired"] == true {
			expired++
		}
	}
	return fmt.Sprintf("Mx-Panel 每日汇总 · %s（UTC）\n\n服务器网卡观测流量\n接收：%.3f GiB；发送：%.3f GiB\n昨日有有效流量区间：%d / %d 台\n累计有效区间：%.2f 服务器小时；记录缺口：%d\n当前开启历史采样：%d 台\n\n订阅当前状态（生成时快照）\n总订阅：%d；已设额度/有效期：%d\n额度用尽：%d；已到期：%d\n\n无有效区间的服务器未计入流量；缺口不补算。网卡流量不是订阅账单，订阅状态不是昨日新增用量。", date, rx/(1<<30), tx/(1<<30), observed, len(rows), seconds/3600, gaps, enabled, len(profiles), configured, exhausted, expired), nil
}
