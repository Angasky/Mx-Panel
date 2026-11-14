package monitorhistory

import (
	"errors"
	"math"
	"sort"
	"time"
)

type RangeView struct {
	Start           string `json:"start"`
	End             string `json:"end"`
	Mode            string `json:"mode"`
	RX              uint64 `json:"rx"`
	TX              uint64 `json:"tx"`
	Used            uint64 `json:"used"`
	ObservedSeconds int64  `json:"observedSeconds"`
	ElapsedSeconds  int64  `json:"elapsedSeconds"`
	Gaps            int    `json:"gaps"`
	RequestedDays   int    `json:"requestedDays"`
	MissingDays     int    `json:"missingDays"`
	Overflow        bool   `json:"overflow"`
	Days            []Day  `json:"days"`
}

// RangeSummary is a read-only UTC inclusive-date view. Missing records never
// become synthetic zero-traffic days; recent and extended history are deduped.
func RangeSummary(s State, start, end, mode string, now time.Time) (RangeView, error) {
	v := RangeView{Start: start, End: end, Mode: mode, Days: []Day{}}
	first, err := time.Parse("2006-01-02", start)
	if err != nil {
		return v, errors.New("开始日期无效")
	}
	last, err := time.Parse("2006-01-02", end)
	if err != nil {
		return v, errors.New("结束日期无效")
	}
	now = now.UTC()
	if first.Year() < 2000 || last.Year() > 2200 || last.Before(first) || end > now.Format("2006-01-02") {
		return v, errors.New("日期须为 2000–2200 年且开始不晚于结束，结束不晚于今天（UTC）")
	}
	v.RequestedDays = int(last.Sub(first)/(24*time.Hour)) + 1
	if v.RequestedDays > 400 {
		return v, errors.New("一次最多查询 400 个自然日")
	}
	if mode != "sum" && mode != "max" && mode != "rx" && mode != "tx" {
		return v, errors.New("统计口径无效")
	}
	until := last.AddDate(0, 0, 1)
	if until.After(now) {
		until = now
	}
	v.ElapsedSeconds = int64(until.Sub(first).Seconds())
	byDate := map[string]Day{}
	// Recent daily records are authoritative for overlap with extended history.
	for _, list := range [][]Day{s.BillingDays, s.Days} {
		for _, d := range list {
			if d.Date >= start && d.Date <= end {
				if _, err := time.Parse("2006-01-02", d.Date); err != nil || d.Seconds < 0 || d.Seconds > 86400 || d.Gaps < 0 {
					return v, errors.New("日汇总数据无效")
				}
				byDate[d.Date] = d
			}
		}
	}
	keys := []string{}
	for date := range byDate {
		keys = append(keys, date)
	}
	sort.Strings(keys)
	add := func(a, b uint64) uint64 {
		if math.MaxUint64-a < b {
			v.Overflow = true
			return math.MaxUint64
		}
		return a + b
	}
	for _, date := range keys {
		d := byDate[date]
		v.Days = append(v.Days, d)
		v.RX = add(v.RX, d.RX)
		v.TX = add(v.TX, d.TX)
		v.ObservedSeconds += d.Seconds
		if d.Gaps > math.MaxInt-v.Gaps {
			return v, errors.New("缺口次数超出范围")
		}
		v.Gaps += d.Gaps
	}
	v.MissingDays = v.RequestedDays - len(v.Days)
	switch mode {
	case "rx":
		v.Used = v.RX
	case "tx":
		v.Used = v.TX
	case "max":
		v.Used = max(v.RX, v.TX)
	case "sum":
		v.Used = add(v.RX, v.TX)
	}
	return v, nil
}
