package web

import (
	"context"
	"crypto/rand"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/subsource"
	"time"
)

func externalInterval(row externalSource) time.Duration {
	switch row.Interval {
	case 1, 6, 12, 24:
		return time.Duration(row.Interval) * time.Hour
	}
	return 24 * time.Hour
}
func recordExternalResult(row *externalSource, info subsource.Traffic, err error, now time.Time) {
	row.ScheduleRevision = rand.Text()
	row.Checked = now.Unix()
	row.Error = ""
	delay := externalInterval(*row)
	if err != nil {
		row.Error = "未获取有效流量信息：上游未提供标准响应头，或请求失败。旧快照不代表当前剩余额度。"
		if row.Failures < 6 {
			row.Failures++
		}
		delay *= time.Duration(1 << row.Failures)
		if delay > 24*time.Hour {
			delay = 24 * time.Hour
		}
	} else {
		row.Failures = 0
		sample := externalSnapshot{Time: now.Unix(), Traffic: info}
		samples := row.Samples
		if len(samples) > 0 && time.Unix(samples[len(samples)-1].Time, 0).UTC().Format("2006-01-02") == now.UTC().Format("2006-01-02") {
			samples[len(samples)-1] = sample
		} else {
			samples = append(samples, sample)
		}
		row.Samples = samples
	}
	row.Next = 0
	if row.Auto {
		row.Next = now.Add(delay).Unix()
	}
}

// One due source per tick, oldest first. Network I/O never holds the data lock
// or delays monitor sampling and notification delivery.
func (s *Server) pollExternalTraffic(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	s.externalMu.Lock()
	rows, e := s.readExternal()
	if e != nil {
		s.externalMu.Unlock()
		return
	}
	now := s.now()
	trimExternal(rows, now)
	idx := -1
	for i, row := range rows {
		if row.Auto && row.Next <= now.Unix() && now.Unix()-row.Checked >= 60 && (idx < 0 || row.Next < rows[idx].Next) {
			idx = i
		}
	}
	if idx < 0 {
		s.externalMu.Unlock()
		return
	}
	// Persist a lease before contacting the provider, avoiding restart storms.
	rows[idx].Next = now.Add(externalInterval(rows[idx])).Unix()
	selected := rows[idx]
	if s.saveExternal(rows) != nil {
		s.externalMu.Unlock()
		return
	}
	s.externalMu.Unlock()
	manager, e := s.remoteManager()
	var info subsource.Traffic
	if e == nil {
		var secret map[string]any
		secret, e = manager.OpenUser(selected.Secret)
		if e == nil {
			url, _ := secret["url"].(string)
			if url == "" {
				e = errors.New("missing URL")
			} else {
				call, cancel := context.WithTimeout(ctx, 20*time.Second)
				fetch := s.fetchExternalTraffic
				if fetch == nil {
					fetch = subsource.NewClient().FetchTraffic
				}
				info, e = fetch(call, url)
				cancel()
			}
		}
	}
	if ctx.Err() != nil {
		return
	}
	s.externalMu.Lock()
	defer s.externalMu.Unlock()
	rows, err := s.readExternal()
	if err != nil {
		return
	}
	for i, row := range rows {
		// Discard in-flight results after disabling, deleting, rescheduling or a manual refresh.
		if row.ScheduleRevision == selected.ScheduleRevision && row.ID == selected.ID && row.Auto && row.Next == selected.Next && row.Checked == selected.Checked && row.Secret == selected.Secret && row.Interval == selected.Interval {
			recordExternalResult(&rows[i], info, e, s.now())
			trimExternal(rows, s.now())
			_ = s.saveExternal(rows)
			return
		}
	}
}
