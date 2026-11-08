package billing

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

func TestPythonDecimalBandwidthAndMultiplier(t *testing.T) {
	for _, tc := range []struct {
		raw  any
		want int
	}{
		{nil, 0}, {"", 0}, {" 1.234 ", 1234}, {json.Number("1e-1"), 100},
		{"+1.23000", 1230}, {".5", 500}, {"1_0", 10000}, {"-0", 0},
		{json.Number("1E4"), 10000000}, {1.234, 1234}, {int64(2), 2000},
	} {
		got, err := BandwidthKbps(tc.raw)
		if err != nil || got != tc.want {
			t.Fatalf("%v: %d %v", tc.raw, got, err)
		}
	}
	for _, raw := range []any{true, false, []any{1}, map[string]any{}, "1/2", "0x1p0", "NaN", "Infinity", "1e99999999", "1e-99999999", "-1", "0.099", "1.0001", "10000.001", strings.Repeat("0", 257), math.Inf(1)} {
		if _, err := BandwidthKbps(raw); err == nil {
			t.Fatalf("invalid bandwidth accepted: %v", raw)
		}
	}
	for _, tc := range []struct {
		raw  string
		want int64
	}{
		{"1e-3", 1}, {"100.0000", 100000}, {" 1.234 ", 1234}, {"1_0", 10000},
	} {
		got, err := MultiplierUnits(tc.raw)
		if err != nil || got != tc.want {
			t.Fatal(tc, got, err)
		}
	}
	for _, raw := range []string{"1/2", "0x1p0", "0.0001", "100.001", "", "true"} {
		if _, err := MultiplierUnits(raw); err == nil {
			t.Fatal("invalid multiplier", raw)
		}
	}
}
