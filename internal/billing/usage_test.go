package billing

import (
	"math"
	"testing"
	"time"
)

func TestNodeMultiplierRemaindersDoNotCreateDrift(t *testing.T) {
	for _, units := range []int64{0, 1, 333, 999, 1000, 1500, 100000} {
		previous := Binding{MultiplierUnits: units, Source: "authenticated-client"}
		total := int64(0)
		for i := int64(1); i <= 3000; i++ {
			delta, err := Compute(previous, Counter{Up: i, Down: i * 2, Source: "authenticated-client"})
			if err != nil {
				t.Fatal(err)
			}
			previous = delta.Next
			total += delta.BilledUp
		}
		if total != 3*units || previous.UpRemainder != 0 {
			t.Fatal("rounding drift", units, total)
		}
		delta, err := Compute(previous, Counter{Up: 3000, Down: 6000, Source: "authenticated-client"})
		if err != nil || delta.BilledUp != 0 || delta.BilledDown != 0 {
			t.Fatal("idle counter created traffic")
		}
	}
}
func TestResetsSourcesAndOverflow(t *testing.T) {
	previous := Binding{Up: 100, Down: 200, Source: "authenticated-client", MultiplierUnits: 1000}
	delta, err := Compute(previous, Counter{Up: 3, Down: 4, Source: "authenticated-client"})
	if err != nil || delta.RawUp != 3 || delta.BilledDown != 4 {
		t.Fatal("counter reset lost new traffic")
	}
	if _, err = Compute(previous, Counter{Up: 101, Down: 202, Source: "inbound-port"}); err == nil {
		t.Fatal("counter source silently mixed")
	}
	if _, err = Compute(Binding{MultiplierUnits: 100000}, Counter{Up: math.MaxInt64, Source: "test"}); err == nil {
		t.Fatal("overflow accepted")
	}
	for _, input := range []string{"NaN", "Inf", "-1", "101", "0.0001"} {
		if _, err = MultiplierUnits(input); err == nil {
			t.Fatal("invalid multiplier accepted", input)
		}
	}
	if n, err := MultiplierUnits("1.234"); err != nil || n != 1234 {
		t.Fatal("decimal multiplier conversion changed")
	}
}
func TestExpiryQuotaHeadersAndCalendarMonths(t *testing.T) {
	now := time.Date(2026, 1, 31, 12, 34, 56, 0, time.UTC)
	if Month(now, 1).Format(time.DateOnly) != "2026-02-28" {
		t.Fatal("monthly anchor overflowed")
	}
	total := int64(100)
	expire := now.Unix()
	usage := Usage{Enabled: true, Enforce: true, Upload: 40, Download: 60, Total: &total}
	if !usage.Blocked(now) {
		t.Fatal("exhausted quota not blocked")
	}
	usage.Download = 59
	if usage.Blocked(now) {
		t.Fatal("remaining byte incorrectly blocked")
	}
	usage.Expire = &expire
	if !usage.Blocked(now) {
		t.Fatal("expired subscription not blocked")
	}
	usage.Enforce = false
	if usage.Blocked(now) {
		t.Fatal("display-only quota blocked subscription")
	}
	header, err := usage.Userinfo()
	if err != nil || header == "" {
		t.Fatal("usage header missing")
	}
	usage.Enabled = false
	header, err = usage.Userinfo()
	if err != nil || header != "" {
		t.Fatal("unconfigured subscription emitted fake usage")
	}
}
