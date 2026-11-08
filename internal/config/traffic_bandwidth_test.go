package config

import (
	"testing"
	"time"
)

func TestTrafficInfoExposesDedicatedBandwidthWithoutRecoveryData(t *testing.T) {
	info, err := TrafficInfo(Document{"id": "clash", "remoteNodes": []any{Document{"scope": "inbound", "dedicated": true, "status": "active", "sealedUser": "secret", "bandwidth": Document{"uploadKbps": 125, "downloadKbps": 2500, "mode": "policing", "recoverySecret": "hidden"}}}}, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	binding := info["bindings"].([]any)[0].(Document)
	bandwidth := binding["bandwidth"].(Document)
	if binding["dedicated"] != true || bandwidth["uploadKbps"] != 125 || bandwidth["downloadKbps"] != 2500 {
		t.Fatal("displayed policy lost", binding)
	}
	if binding["sealedUser"] != nil || bandwidth["recoverySecret"] != nil {
		t.Fatal("private recovery metadata exposed")
	}
}
