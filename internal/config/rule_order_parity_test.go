package config

import (
	"reflect"
	"testing"
)

func TestPythonRuleMoveOffsetsClampAndSwap(t *testing.T) {
	for _, tc := range []struct {
		direction any
		expected  []any
	}{
		{2, []any{"A", "D", "C", "B"}},
		{-8, []any{"B", "A", "C", "D"}},
		{int(^uint(0) >> 1), []any{"A", "D", "C", "B"}},
		{-int(^uint(0)>>1) - 1, []any{"B", "A", "C", "D"}},
		{0, []any{"A", "B", "C", "D"}},
		{nil, []any{"A", "B", "C", "D"}},
	} {
		doc := Document{"rules": []any{"A", "B", "C", "D"}}
		payload := Document{"raw": "B"}
		if tc.direction != nil {
			payload["direction"] = tc.direction
		}
		if err := MoveRule(doc, payload); err != nil || !reflect.DeepEqual(doc["rules"], tc.expected) {
			t.Fatal(tc.direction, doc, err)
		}
	}
}
