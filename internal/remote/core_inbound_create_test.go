package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestStandaloneInboundCreateRecoversAfterInterruptedWrite(t *testing.T) {
	testStandaloneInboundCreate(t, "vmess-tcp", []string{"xray", "sing-box"})
}

func TestStandaloneRealityUsesVerifiedSNI(t *testing.T) {
	testStandaloneInboundCreate(t, "vless-reality", []string{"xray"})
}

func TestStandaloneTLSInboundCreateChecksCertificateBeforeWriting(t *testing.T) {
	testStandaloneInboundCreate(t, "trojan-tls", []string{"xray", "sing-box"})
	testStandaloneInboundCreate(t, "vless-ws-tls", []string{"xray", "sing-box"})
	testStandaloneInboundCreate(t, "hysteria2", []string{"sing-box"})
}

func testStandaloneInboundCreate(t *testing.T, template string, kinds []string) {
	t.Helper()
	for _, kind := range kinds {
		t.Run(kind+"/"+template, func(t *testing.T) {
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
			payload := Record{"template": template, "remark": "test-node", "operationId": strings.Repeat("a", 32)}
			if tlsTemplate(template) {
				payload["serverName"], payload["certFile"], payload["keyFile"] = "node.example.net", "/etc/test.crt", "/etc/test.key"
			}
			key, hash, err := createRequestIdentity("clash", payload)
			if err != nil {
				t.Fatal(err)
			}
			raw := []byte(`{"inbounds":[{"tag":"manual","port":443,"listen_port":443}],"outbounds":[{"tag":"direct"}]}`)
			writes, checks := 0, 0
			validCertificate := false
			interruptWrite := false
			rejectWrite := false
			run := func(_ context.Context, command string, _ int) (string, error) {
				if strings.HasPrefix(command, "base64 < ") {
					return base64.StdEncoding.EncodeToString(raw), nil
				}
				if strings.HasPrefix(command, "test -x ") {
					return "with_v2ray_api", nil
				}
				if strings.Contains(command, "openssl x509") {
					checks++
					if !validCertificate {
						return "", errors.New("certificate check failed")
					}
					return "MXIOC_CERTIFICATE_OK", nil
				}
				if rejectWrite {
					return "MXIOC_CORE_VALIDATION_FAILED", errors.New("invalid candidate")
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
				if writes == 1 || interruptWrite {
					interruptWrite = false
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
			if tlsTemplate(template) {
				if _, err := create(hash, payload); err == nil || writes != 0 || checks != 1 {
					t.Fatal("invalid certificate did not block remote write")
				}
				validCertificate = true
			}
			if template == "vless-reality" {
				payload["serverName"], payload["sniAddress"] = "example.net", "1.1.1.1"
				_, hash, err = createRequestIdentity("clash", payload)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := create(hash, payload); err == nil || writes != 0 {
					t.Fatal("unverified Reality SNI did not block writes")
				}
				record, err := m.Record(serverID)
				if err != nil {
					t.Fatal(err)
				}
				scanner := m.sniState()
				scanner.cache[sniCacheKey{serverID, certificateRevision(record), "example.net", "1.1.1.1"}] = sniCached{scanner.now(), true}
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
			if template == "hysteria2" && (row["protocol"] != "hysteria2" ||
				anyRecords(doc["inbounds"])[1]["type"] != "hysteria2") {
				t.Fatal("sing-box must receive native Hysteria2 configuration")
			}
			port, err := parsedPort(row["port"], 0)
			if err != nil || port < 20001 || value(row["id"]) != value(replayed["inbound"].(Record)["id"]) {
				t.Fatal("automatic port or ID changed", err)
			}
			if template == "vless-ws-tls" {
				id, _ := strconv.Atoi(value(row["id"]))
				version, err := InboundVersion(row)
				if err != nil {
					t.Fatal(err)
				}
				edit := func(payload Record) (Record, error) {
					record, err := m.Record(serverID)
					if err != nil {
						return nil, err
					}
					return m.changeManagedCoreInbound(context.Background(), serverID, kind, record, id, version, payload,
						func(old, next Record) error {
							if !sameCoreInbound(old["settings"].(Record), next["settings"].(Record)) {
								t.Fatal("edit changed client credentials")
							}
							return nil
						}, nil, run)
				}
				if _, err := edit(Record{"port": 443}); err == nil || writes != 2 {
					t.Fatal("occupied port was accepted")
				}
				patch := Record{"port": 19998, "wsPath": "/go-updated"}
				rejectWrite = true
				if _, err := edit(patch); !errors.Is(err, errCoreValidation) || writes != 2 {
					t.Fatal("rejected candidate should leave remote unchanged", err)
				}
				rejectWrite = false
				interruptWrite = true
				if _, err := edit(patch); err == nil || writes != 3 {
					t.Fatal("expected interrupted edit")
				}
				m, err = Open(root)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := edit(Record{"wsPath": "/different"}); err == nil || writes != 3 {
					t.Fatal("different payload accepted during recovery")
				}
				if _, err := edit(patch); err != nil || writes != 4 {
					t.Fatal("could not resume edit", err)
				}
				replay, err := create(hash, payload)
				if err != nil || replay["reused"] != true || writes != 4 {
					t.Fatal("create replay did not recognize edited node", err)
				}
				fields := managedCoreFields(replay["inbound"].(Record))
				if fields["wsPath"] != "/go-updated" || value(fields["port"]) != "19998" {
					t.Fatal("updated settings were not persisted")
				}
			}
			if template != "vmess-tcp" {
				return
			}
			inboundID, err := strconv.Atoi(value(row["id"]))
			if err != nil {
				t.Fatal(err)
			}
			change := func(expected string, patch Record, guard func(Record) error) (Record, error) {
				record, err := m.Record(serverID)
				if err != nil {
					return nil, err
				}
				return m.changeManagedCoreInbound(context.Background(), serverID, kind, record, inboundID, expected, patch,
					func(old, next Record) error {
						if old["remark"] != "test-node" || next["remark"] != "renamed" || next["tag"] != old["tag"] {
							t.Fatal("unexpected rename", old["remark"], next["remark"])
						}
						return nil
					}, guard, run)
			}
			version, err := InboundVersion(row)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := change(version, Record{"remark": "renamed"}, nil); err != nil || writes != 2 {
				t.Fatal("rename should save metadata only", err)
			}
			guard := func(old Record) error {
				if old == nil || old["remark"] != "renamed" {
					t.Fatal("delete guard did not see the current row")
				}
				return nil
			}
			if _, err := change(version, nil, guard); err == nil || writes != 2 {
				t.Fatal("stale identity should not delete")
			}
			row["remark"] = "renamed"
			version, err = InboundVersion(row)
			if err != nil {
				t.Fatal(err)
			}
			original := raw
			doc["route"] = Record{"rules": []any{Record{"inbound": []any{row["tag"]}}}}
			raw, err = json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := change(version, nil, guard); err == nil || writes != 2 {
				t.Fatal("referenced inbound should not be removed")
			}
			raw = original
			interruptWrite = true
			if _, err := change(version, nil, guard); err == nil || writes != 3 {
				t.Fatal("interrupted delete should be pending")
			}
			m, err = Open(root)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := change(version, nil, guard); err != nil || writes != 4 {
				t.Fatal("retry should confirm the persisted deletion", err)
			}
			replay, err := change(version, nil, func(old Record) error {
				if old != nil {
					t.Fatal("confirmed deletion should be absent")
				}
				return nil
			})
			if err != nil || replay["alreadyMissing"] != true || writes != 4 {
				t.Fatal("confirmed deletion replay should not write", err)
			}
			if _, err := create(hash, payload); err == nil || writes != 4 {
				t.Fatal("old create request must not resurrect deleted inbound")
			}
			if err := json.Unmarshal(raw, &doc); err != nil || len(anyRecords(doc["inbounds"])) != 1 ||
				anyRecords(doc["inbounds"])[0]["tag"] != "manual" {
				t.Fatal("delete changed unrelated inbounds", err)
			}

		})
	}
}
