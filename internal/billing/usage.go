// Package billing performs byte accounting with integer arithmetic. Fractional
// node multipliers carry a remainder instead of rounding each poll separately.
package billing

import (
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"time"
)

func MultiplierUnits(value string) (int64, error) {
	if strings.TrimSpace(value) != value || value == "" {
		return 0, errors.New("流量倍率无效")
	}
	ratio, ok := new(big.Rat).SetString(value)
	if !ok || ratio.Sign() < 0 || ratio.Cmp(big.NewRat(100, 1)) > 0 {
		return 0, errors.New("流量倍率范围为 0–100")
	}
	ratio.Mul(ratio, big.NewRat(1000, 1))
	if !ratio.IsInt() || !ratio.Num().IsInt64() {
		return 0, errors.New("流量倍率最多支持三位小数")
	}
	return ratio.Num().Int64(), nil
}

type Counter struct {
	Up, Down int64
	Source   string
}
type Binding struct {
	Up, Down, UpRemainder, DownRemainder, MultiplierUnits int64
	Source                                                string
}
type Delta struct {
	RawUp, RawDown, BilledUp, BilledDown int64
	Next                                 Binding
}

func billed(delta, units, remainder int64) (int64, int64, error) {
	if delta < 0 || units < 0 || units > 100000 || remainder < 0 || remainder >= 1000 {
		return 0, 0, errors.New("流量计量参数无效")
	}
	number := new(big.Int).Mul(big.NewInt(delta), big.NewInt(units))
	number.Add(number, big.NewInt(remainder))
	rest := new(big.Int)
	number.QuoRem(number, big.NewInt(1000), rest)
	if !number.IsInt64() {
		return 0, 0, errors.New("流量计量结果超过整数范围")
	}
	return number.Int64(), rest.Int64(), nil
}
func Compute(previous Binding, current Counter) (Delta, error) {
	if previous.Up < 0 || previous.Down < 0 || current.Up < 0 || current.Down < 0 || current.Source == "" {
		return Delta{}, errors.New("流量计数无效")
	}
	if previous.Source != "" && previous.Source != current.Source {
		return Delta{}, errors.New("计数来源变化，必须显式重建基线，不能混合计费")
	}
	up := current.Up - previous.Up
	down := current.Down - previous.Down
	if current.Up < previous.Up {
		up = current.Up
	}
	if current.Down < previous.Down {
		down = current.Down
	}
	chargedUp, remainderUp, err := billed(up, previous.MultiplierUnits, previous.UpRemainder)
	if err != nil {
		return Delta{}, err
	}
	chargedDown, remainderDown, err := billed(down, previous.MultiplierUnits, previous.DownRemainder)
	if err != nil {
		return Delta{}, err
	}
	next := previous
	next.Up = current.Up
	next.Down = current.Down
	next.UpRemainder = remainderUp
	next.DownRemainder = remainderDown
	next.Source = current.Source
	return Delta{RawUp: up, RawDown: down, BilledUp: chargedUp, BilledDown: chargedDown, Next: next}, nil
}
func Add(left, right int64) (int64, error) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, errors.New("流量用量超过整数范围")
	}
	return left + right, nil
}

type Usage struct {
	Enabled, Enforce, Revoked bool
	Upload, Download          int64
	Total, Expire             *int64
}

func (u Usage) Blocked(now time.Time) bool {
	return u.Revoked || u.Enabled && u.Enforce && (u.Expire != nil && *u.Expire <= now.Unix() || u.Total != nil && (u.Upload >= *u.Total || u.Download >= *u.Total-u.Upload))
}
func (u Usage) Userinfo() (string, error) {
	if !u.Enabled {
		return "", nil
	}
	if u.Upload < 0 || u.Download < 0 || u.Total != nil && *u.Total < 0 || u.Expire != nil && *u.Expire < 0 {
		return "", errors.New("流量信息无效")
	}
	total := int64(0)
	if u.Total != nil {
		total = *u.Total
	}
	result := "upload=" + strconv.FormatInt(u.Upload, 10) + "; download=" + strconv.FormatInt(u.Download, 10) + "; total=" + strconv.FormatInt(total, 10)
	if u.Expire != nil {
		result += "; expire=" + strconv.FormatInt(*u.Expire, 10)
	}
	return result, nil
}

// Month follows the original calendar-month renewal rule: Jan 31 + one month
// becomes the last day of February, rather than overflowing into March.
func Month(anchor time.Time, months int) time.Time {
	first := time.Date(anchor.Year(), anchor.Month()+time.Month(months), 1, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), anchor.Location())
	last := time.Date(first.Year(), first.Month()+1, 0, 0, 0, 0, 0, anchor.Location()).Day()
	day := anchor.Day()
	if day > last {
		day = last
	}
	return time.Date(first.Year(), first.Month(), day, anchor.Hour(), anchor.Minute(), anchor.Second(), anchor.Nanosecond(), anchor.Location())
}
