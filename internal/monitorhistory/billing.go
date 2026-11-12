package monitorhistory

import (
	"errors"
	"math"
	"time"
)

// Billing describes an observation budget; it never stops nodes or charges users.
type BillingConfig struct {
	Anchor string `json:"anchor"`
	Months int    `json:"months"`
	Mode   string `json:"mode"`
	Limit  uint64 `json:"limit"`
}

func (c BillingConfig) Validate() error {
	t, e := time.Parse("2006-01-02", c.Anchor)
	if e != nil || t.Year() < 2000 || t.Year() > 2200 {
		return errors.New("周期起点必须是 2000–2200 年的有效日期")
	}
	switch c.Months {
	case 1, 3, 6, 12:
	default:
		return errors.New("周期只能为 1、3、6 或 12 个月")
	}
	switch c.Mode {
	case "sum", "max", "rx", "tx":
	default:
		return errors.New("统计模式无效")
	}
	if c.Limit > 9007199254740991 {
		return errors.New("流量限额超出可精确显示的范围")
	}
	return nil
}

// Calculate each boundary from the original anchor, avoiding Jan 31 -> Mar 3
// and avoiding a permanent shift to day 28 after February.
func billingBoundary(anchor time.Time, months int) time.Time {
	first := time.Date(anchor.Year(), anchor.Month()+time.Month(months), 1, 0, 0, 0, 0, time.UTC)
	last := first.AddDate(0, 1, -1).Day()
	day := anchor.Day()
	if day > last {
		day = last
	}
	return first.AddDate(0, 0, day-1)
}

type BillingView struct {
	Config          *BillingConfig `json:"config"`
	Enabled         bool           `json:"enabled"`
	Start           string         `json:"start"`
	End             string         `json:"end"`
	RX              uint64         `json:"rx"`
	TX              uint64         `json:"tx"`
	Used            uint64         `json:"used"`
	Remaining       uint64         `json:"remaining"`
	Percent         float64        `json:"percent"`
	Exceeded        bool           `json:"exceeded"`
	Overflow        bool           `json:"overflow"`
	ObservedSeconds int64          `json:"observedSeconds"`
	ElapsedSeconds  int64          `json:"elapsedSeconds"`
	Gaps            int            `json:"gaps"`
	Days            []Day          `json:"days"`
}

func BillingSummary(s State, now time.Time) BillingView {
	v := BillingView{Config: s.Billing, Enabled: s.Enabled, Days: []Day{}}
	if s.Billing == nil || s.Billing.Validate() != nil {
		return v
	}
	c := s.Billing
	anchor, _ := time.Parse("2006-01-02", c.Anchor)
	now = now.UTC()
	if now.Before(anchor) {
		return v
	}
	months := (now.Year()-anchor.Year())*12 + int(now.Month()-anchor.Month())
	n := months / c.Months * c.Months
	start := billingBoundary(anchor, n)
	if start.After(now) {
		n -= c.Months
		start = billingBoundary(anchor, n)
	}
	end := billingBoundary(anchor, n+c.Months)
	v.Start = start.Format("2006-01-02")
	v.End = end.Format("2006-01-02")
	v.ElapsedSeconds = int64(now.Sub(start).Seconds())
	add := func(a, b uint64) uint64 {
		if math.MaxUint64-a < b {
			v.Overflow = true
			return math.MaxUint64
		}
		return a + b
	}
	for _, d := range s.BillingDays {
		if d.Date < v.Start || d.Date >= v.End || d.Date > now.Format("2006-01-02") {
			continue
		}
		v.Days = append(v.Days, d)
		v.RX = add(v.RX, d.RX)
		v.TX = add(v.TX, d.TX)
		v.ObservedSeconds += d.Seconds
		v.Gaps += d.Gaps
	}
	switch c.Mode {
	case "rx":
		v.Used = v.RX
	case "tx":
		v.Used = v.TX
	case "max":
		v.Used = v.RX
		if v.TX > v.Used {
			v.Used = v.TX
		}
	case "sum":
		v.Used = add(v.RX, v.TX)
	}
	if c.Limit > 0 {
		v.Percent = float64(v.Used) / float64(c.Limit) * 100
		v.Exceeded = v.Used >= c.Limit
		if !v.Exceeded {
			v.Remaining = c.Limit - v.Used
		}
	}
	return v
}
func (s *Store) SetBilling(id string, c *BillingConfig, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if c != nil {
		if e := c.Validate(); e != nil {
			return e
		}
		if c.Anchor > now.UTC().Format("2006-01-02") {
			return errors.New("周期起点不能晚于今天（UTC）")
		}
	}
	state, e := s.read(id)
	if e != nil {
		return e
	}
	trim(&state, now)
	if c == nil {
		state.BillingDays = nil
	} else if state.Billing == nil {
		state.BillingDays = append([]Day(nil), state.Days...)
	}
	state.Billing = c
	return s.write(id, state)
}
