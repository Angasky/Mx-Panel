package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCoreReadWriteVerificationAndStaleRejection(t *testing.T) {
	raw := []byte(`{"inbounds":[],"outbounds":[],"unknown":9007199254740993}`)
	writes := 0
	next := Record{"inbounds": []any{}, "outbounds": []any{}, "unknown": json.Number("9007199254740993"), "new": true}
	run := func(ctx context.Context, script string, limit int) (string, error) {
		if strings.HasPrefix(script, "base64 <") {
			return base64.StdEncoding.EncodeToString(raw), nil
		}
		writes++
		raw, _ = json.Marshal(next)
		return "MXIOC_CORE_APPLIED\n", nil
	}
	result, err := coreOperation(context.Background(), "xray", "", nil, run)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = coreOperation(context.Background(), "xray", strings.Repeat("0", 64), next, run); err == nil || writes != 0 {
		t.Fatal("stale write executed")
	}
	result, err = coreOperation(context.Background(), "xray", value(result["version"]), next, run)
	if err != nil || result["updated"] != true || writes != 1 {
		t.Fatal(result, err, writes)
	}
}
func TestCoreWriteFailureIsNotReplayed(t *testing.T) {
	for _, marker := range []string{"", "MXIOC_CORE_ROLLED_BACK", "MXIOC_CORE_ROLLBACK_FAILED"} {
		writes := 0
		raw := []byte(`{"inbounds":[],"outbounds":[]}`)
		run := func(ctx context.Context, script string, limit int) (string, error) {
			if strings.HasPrefix(script, "base64 <") {
				return base64.StdEncoding.EncodeToString(raw), nil
			}
			writes++
			return marker, errors.New("fixture failure")
		}
		result, _ := coreOperation(context.Background(), "sing-box", "", nil, run)
		_, err := coreOperation(context.Background(), "sing-box", value(result["version"]), Record{"inbounds": []any{}}, run)
		if err == nil || writes != 1 {
			t.Fatal("unconfirmed write accepted or replayed", err, writes)
		}
	}
}
