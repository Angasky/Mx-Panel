package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestStandaloneInboundCreateRecoversAfterInterruptedWrite(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			m, err := Open(root)
			if err != nil {
				t.Fatal(err)
			}
			server := serverPayload()
			server["installType"] = kind
			delete(server, "panelAddress")
			public, err := m.Save(server)
			if err != nil {
				t.Fatal(err)
			}
			serverID := value(public["id"])
			payload := Record{"template": "vmess-tcp", "remark": "VMess", "operationId": strings.Repeat("a", 32)}
			key, hash, err := createRequestIdentity("clash", payload)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"inbounds":[{"tag":"manual","port":443,"listen_port":443}],"outbounds":[{"tag":"direct"}]}`)
			writes := 0
			run := func(_ context.Context, command string, _ int) (string, error) {
				if strings.HasPrefix(command, "base64 < ") {
					return base64.StdEncoding.EncodeToString(raw), nil
				}
				if strings.HasPrefix(command, "test -x ") {
					return "with_v2ray_api", nil
				}
				_, tail, ok := strings.Cut(command, "printf '%s' '")
				if !ok {
					t.Fatal("missing candidate")
				}
				encoded, _, _ := strings.Cut(tail, "'")
				var err error
				raw, err = base64.StdEncoding.DecodeString(encoded)
				if err != nil {
					t.Fatal(err)
				}
				writes++
				if writes == 1 {
					return "", errors.New("SSH disconnected after write")
				}
				return "MXIOC_CORE_APPLIED", nil
			}
			create := func(requestHash string, request Record) (Record, error) {
				record, err := m.Record(serverID)
				if err != nil {
					return nil, err
				}
				return m.createCoreInbound(context.Background(), serverID, kind, key, requestHash, record, request, run)
			}
			occupied := Record{"template": "vmess-tcp", "port": 443}
			if _, err := create("occupied", occupied); err == nil || writes != 0 {
				t.Fatal("occupied port should not change configuration")
			}
			if _, err := create(hash, payload); err == nil || writes != 1 {
				t.Fatal("interrupted request should be pending")
			}
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			result, err := create(hash, payload)
			if err != nil || writes != 2 {
				t.Fatal("retry did not recover the same inbound", err)
			}
			replayed, err := create(hash, payload)
			if err != nil || replayed["reused"] != true || writes != 2 {
				t.Fatal("confirmed replay rewrote the configuration", err)
			}
			var doc Record
			if err := json.Unmarshal(raw, &doc); err != nil || len(anyRecords(doc["inbounds"])) != 2 ||
				anyRecords(doc["inbounds"])[0]["tag"] != "manual" {
				t.Fatal("unrelated config changed", err)
			}
			row := result["inbound"].(Record)
			port, err := parsedPort(row["port"], 0)
			if err != nil || port < 20001 || value(row["id"]) != value(replayed["inbound"].(Record)["id"]) {
				t.Fatal("automatic port or ID changed", err)
			}
		})
	}
}
