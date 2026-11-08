package remote

import (
	"context"
	"encoding/json"
	"testing"
)

func TestDedicatedPanelSingleConnectionLifecycle(t *testing.T) {
	for _, protocol := range []string{"shadowsocks", "http", "socks"} {
		t.Run(protocol, func(t *testing.T) {
			p, row, writes, _ := inboundWriteFixture(t)
			(*row)["protocol"] = protocol
			(*row)["settings"] = Record{"method": "aes-128-gcm", "password": "original-secret", "network": "tcp,udp"}
			if protocol != "shadowsocks" {
				(*row)["settings"] = Record{"accounts": []any{Record{"user": "existing-user", "pass": "original-secret"}}}
			}
			original, _ := json.Marshal((*row)["settings"])
			binding, err := DedicatedPasswordBinding(*row, Record{"serverId": "s", "inboundId": 1})
			if err != nil {
				t.Fatal(err)
			}
			for _, op := range []string{"read", "pause", "pause", "resume", "resume"} {
				result, err := dedicatedPanelInbound(context.Background(), p, Record{}, 1, binding, op)
				if err != nil {
					t.Fatal(op, err)
				}
				reading := result["reading"].(Record)
				if reading["source"] != "inbound" || reading["up"] != int64(9007199254740993) {
					t.Fatal("counter source or precision lost", reading)
				}
				current, _ := json.Marshal((*row)["settings"])
				if string(current) != string(original) {
					t.Fatal("credentials changed")
				}
			}
			if writes.Load() != 2 {
				t.Fatal("idempotent restart replayed mutation", writes.Load())
			}
			for i := 0; i < 2; i++ {
				result, err := dedicatedPanelInbound(context.Background(), p, Record{}, 1, binding, "remove")
				if err != nil || result["removed"] != true {
					t.Fatal(result, err)
				}
			}
			if writes.Load() != 3 || *row != nil {
				t.Fatal("remove failed or replayed")
			}
		})
	}
}

func TestDedicatedPanelRejectsChangedCredentialAndCounter(t *testing.T) {
	for _, scenario := range []string{"password", "client", "transport", "missing-count", "wrong-count", "dependency"} {
		t.Run(scenario, func(t *testing.T) {
			p, row, writes, _ := inboundWriteFixture(t)
			(*row)["protocol"] = "shadowsocks"
			(*row)["settings"] = Record{"method": "aes-128-gcm", "password": "original"}
			binding, err := DedicatedPasswordBinding(*row, Record{})
			if err != nil {
				t.Fatal(err)
			}
			record := Record{}
			op := "read"
			switch scenario {
			case "password":
				(*row)["settings"].(Record)["password"] = "changed"
			case "client":
				(*row)["settings"].(Record)["clients"] = []any{Record{"password": "another"}}
			case "transport":
				(*row)["streamSettings"].(Record)["network"] = "ws"
			case "missing-count":
				delete(*row, "up")
			case "wrong-count":
				(*row)["up"] = json.Number("1.5")
			case "dependency":
				record["meters"] = Record{"1": 24001}
				op = "remove"
			}
			if _, err := dedicatedPanelInbound(context.Background(), p, record, 1, binding, op); err == nil {
				t.Fatal("unsafe operation accepted")
			}
			if writes.Load() != 0 {
				t.Fatal("mutated unverified inlet")
			}
		})
	}
}
