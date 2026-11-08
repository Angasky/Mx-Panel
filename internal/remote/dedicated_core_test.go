package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

func TestDedicatedCoreSinglePasswordLifecycleRecovery(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			m, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			payload := serverPayload()
			payload["installType"] = kind
			delete(payload, "panelAddress")
			public, err := m.Save(payload)
			if err != nil {
				t.Fatal(err)
			}
			server := value(public["id"])
			row := Record{"id": 1, "tag": "mxioc-inbound-1", "port": 24001, "protocol": "shadowsocks", "enable": true, "settings": Record{"method": "aes-128-gcm", "password": "original-password", "network": "tcp,udp"}, "streamSettings": Record{"network": "tcp", "security": "none"}}
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			raw, _ := json.Marshal(Record{"inbounds": []any{native}, "outbounds": []any{}})
			state, _ := m.SealUser(Record{"inbounds": []any{row}})
			if err = m.updateCoreUserState(server, "", "", state, ""); err != nil {
				t.Fatal(err)
			}
			binding, err := DedicatedPasswordBinding(row, Record{"serverId": server, "inboundId": 1, "operationId": "existing", "status": "provisioning"})
			if err != nil {
				t.Fatal(err)
			}
			interrupt := false
			writes, initializations, clears := 0, 0, 0
			failClear := false
			run := func(ctx context.Context, command string, limit int) (string, error) {
				if strings.HasPrefix(command, "base64 < ") {
					return base64.StdEncoding.EncodeToString(raw), nil
				}
				if command == "nft -j list table inet mxioc_usage" {
					return `{"nftables":[{"counter":{"family":"inet","table":"mxioc_usage","name":"up_1","bytes":1000}},{"counter":{"family":"inet","table":"mxioc_usage","name":"down_1","bytes":2000}}]}`, nil
				}
				if strings.Contains(command, "MXIOC_DEDICATED_METER_READY") {
					if strings.Contains(command, "systemctl") {
						initializations++
					}
					return "MXIOC_DEDICATED_METER_READY", nil
				}
				if strings.Contains(command, "MXIOC_LEGACY_METER_CLEARED") {
					if failClear {
						return "", errors.New("offline during meter cleanup")
					}
					clears++
					return "MXIOC_LEGACY_METER_CLEARED", nil
				}
				if strings.Contains(command, "MXIOC_CORE_APPLIED") {
					start := strings.Index(command, "printf '%s' '")
					encoded := strings.SplitN(command[start+len("printf '%s' '"):], "'", 2)[0]
					raw, err = base64.StdEncoding.DecodeString(encoded)
					if err != nil {
						t.Fatal(err)
					}
					writes++
					if interrupt {
						interrupt = false
						return "", errors.New("disconnect after apply")
					}
					return "MXIOC_CORE_APPLIED", nil
				}
				t.Fatal("unexpected command")
				return "", nil
			}
			call := func(op string) (Record, error) {
				record, err := m.Record(server)
				if err != nil {
					return nil, err
				}
				return m.dedicatedCore(context.Background(), server, kind, record, binding, op, run)
			}
			result, err := call("read")
			if err != nil || result["reading"].(Record)["source"] != "inbound" {
				t.Fatal(result, err)
			}
			binding["status"] = "active"
			if _, err = call("read"); err != nil || initializations != 1 {
				t.Fatal("reloaded systemd during ordinary read", initializations, err)
			}
			binding["monthlyPaused"] = true
			interrupt = true
			if _, err = call("pause"); err == nil {
				t.Fatal("interruption reported successful")
			}
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = call("pause"); err != nil {
				t.Fatal(err)
			}
			if writes != 1 || strings.Contains(string(raw), "original-password") {
				t.Fatal("pause failed or replayed")
			}
			binding["monthlyBaselinePending"] = true
			if _, err = call("read"); err != nil {
				t.Fatal("paused counter baseline unavailable", err)
			}
			if _, err = call("resume"); err == nil {
				t.Fatal("resumed before baseline")
			}
			delete(binding, "monthlyBaselinePending")
			if _, err = call("resume"); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(raw), "original-password") {
				t.Fatal("resume changed credentials")
			}
			delete(binding, "monthlyPaused")
			failClear = true
			if _, err = call("remove"); err == nil {
				t.Fatal("cleanup failure hidden")
			}
			if strings.Contains(string(raw), "original-password") {
				t.Fatal("expiry retained original credential")
			}
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			failClear = false
			if _, err = call("remove"); err != nil {
				t.Fatal(err)
			}
			if _, err = call("remove"); err != nil || writes != 3 || clears != 1 {
				t.Fatal("removal retry repeated remote work", writes, clears, err)
			}
		})
	}
}
func TestDedicatedMeterRulesAndStrictCounters(t *testing.T) {
	script, err := dedicatedMeterScript(Record{"2": 24002}, 1, 24001)
	if err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("bash", "-n").CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	command := exec.Command("bash", "-n")
	command.Stdin = strings.NewReader(script)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	if strings.Contains(script, "flush ruleset") || strings.Contains(script, "delete table") {
		t.Fatal("meter setup resets other counters")
	}
	// Exercise awk normalization itself, rather than a substring-only check.
	start := strings.Index(script, "normalize() {")
	end := strings.Index(script, "expected() {")
	command = exec.Command("bash", "-c", script[start:end]+"normalize /dev/stdin")
	command.Stdin = strings.NewReader("chain input {\n counter name up_1\n}\n")
	output, err := command.CombinedOutput()
	if err != nil || !strings.Contains(string(output), "input:counter name up_1") {
		t.Fatal(string(output), err)
	}
	for _, raw := range []string{`{}`, `{"nftables":[{"counter":{"family":"inet","table":"mxioc_usage","name":"up_1","bytes":0}}]}`, `{"nftables":[{"counter":{"family":"inet","table":"mxioc_usage","name":"up_1","bytes":-1}},{"counter":{"family":"inet","table":"mxioc_usage","name":"down_1","bytes":0}}]}`} {
		_, err := readDedicatedMeter(context.Background(), 1, func(context.Context, string, int) (string, error) { return raw, nil })
		if err == nil {
			t.Fatal("missing or negative counters accepted")
		}
	}
	if _, err := dedicatedMeterScript(Record{"2": 24001}, 1, 24001); err == nil {
		t.Fatal("shared port accepted")
	}
}
