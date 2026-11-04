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
		})
	}
}
