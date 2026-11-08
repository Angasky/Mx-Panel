package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBandwidthRatePythonNumericRepresentations(t *testing.T) {
	for _, raw := range []string{`"1.234"`, `1.234`, `1.234e0`, `" 1.2340 "`} {
		var input any
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&input); err != nil {
			t.Fatal(err)
		}
		got, err := bandwidthRate(input)
		if err != nil || got != 1234 {
			t.Fatal(raw, got, err)
		}
	}
}
