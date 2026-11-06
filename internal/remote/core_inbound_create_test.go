package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestStandaloneInboundCreateRecoversAfterInterruptedWrite(t *testing.T) {
	testStandaloneInboundCreate(t, "vmess-tcp", []string{"xray", "sing-box"}, false)
}

func TestStandaloneSSAEADCreateRecoversAfterInterruptedWrite(t *testing.T) {
	for _, template := range []string{"ss-aes-128-gcm", "ss-aes-256-gcm", "ss-chacha20-poly1305"} {
		testStandaloneInboundCreate(t, template, []string{"xray"}, false)
	}
}

func TestStandaloneSS2022CreateRecoversAfterInterruptedWrite(t *testing.T) {
	testStandaloneInboundCreate(t, "ss2022-aes-128", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "ss2022-aes-256", []string{"xray", "sing-box"}, false)
}

func TestStandaloneRealityUsesVerifiedSNI(t *testing.T) {
	testStandaloneInboundCreate(t, "vless-reality", []string{"xray", "sing-box"}, false)
}

func TestStandaloneRelayLifecycle(t *testing.T) {
	testStandaloneInboundCreate(t, "vless-reality", []string{"xray"}, true)
	testStandaloneInboundCreate(t, "vless-reality", []string{"sing-box"}, true)
	testStandaloneInboundCreate(t, "vmess-tcp", []string{"sing-box"}, true)
}

func TestStandaloneTLSInboundCreateChecksCertificateBeforeWriting(t *testing.T) {
	testStandaloneInboundCreate(t, "vless-tcp-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vmess-tcp-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "trojan-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "trojan-ws-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "trojan-grpc-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vless-ws-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vmess-ws-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vless-grpc-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vmess-grpc-tls", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "vless-xhttp-tls", []string{"xray"}, false)
	testStandaloneInboundCreate(t, "hysteria2", []string{"xray", "sing-box"}, false)
	testStandaloneInboundCreate(t, "tuic", []string{"sing-box"}, false)
}

func testStandaloneInboundCreate(t *testing.T, template string, kinds []string, relay bool) {
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
			if relay {
				payload["landingLink"] = "vless://3c5827c6-2f92-4861-a1f8-562d5388bca7@landing.example.net:443"
				if kind == "sing-box" {
					payload["landingLink"] = "hysteria2://fixture-password@landing.example.net:443?sni=landing.example.net&upmbps=50"
				}
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
				var outbound Record
				if relay && request["landingLink"] != nil {
					tag := "mxioc-relay-" + key[:16]
					node, err := links.Parse(value(request["landingLink"]))
					if err != nil {
						return nil, err
					}
					if kind == "sing-box" {
						outbound, err = singRelayOutbound(node, tag)
					} else {
						outbound, err = NodeOutbound(node, tag)
					}
					if err != nil {
						return nil, err
					}
				}
				return m.createCoreInbound(context.Background(), serverID, kind, key, requestHash, record, request, outbound, run)
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
				t.Fatal("interrupted request should be pending", err, writes)
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
			if template == "hysteria2" && kind == "sing-box" && (row["protocol"] != "hysteria2" ||
				anyRecords(doc["inbounds"])[1]["type"] != "hysteria2") {
				t.Fatal("sing-box must receive native Hysteria2 configuration")
			}
			if template == "hysteria2" || template == "tuic" {
				assertStandaloneQUICUser(t, kind, template, row, anyRecords(doc["inbounds"])[1])
			}
			port, err := parsedPort(row["port"], 0)
			if err != nil || port < 20001 || value(row["id"]) != value(replayed["inbound"].(Record)["id"]) {
				t.Fatal("automatic port or ID changed", err)
			}
			if relay {
				proof := coreRelayProof(row)
				doc, err = inboundObject(string(raw))
				if err != nil || proof == nil || verifyCoreRelay(doc, row) != nil || len(anyRecords(doc["outbounds"])) != 2 {
					t.Fatal("relay route and outbound were not committed together with the ingress")
				}
				if kind == "sing-box" {
					outbound := anyRecords(doc["outbounds"])[1]
					tls, _ := outbound["tls"].(Record)
					if outbound["type"] != "hysteria2" || value(outbound["up_mbps"]) != "50" ||
						tls["enabled"] != true || tls["server_name"] != "landing.example.net" {
						t.Fatal("sing-box Hysteria2 landing lost its TLS or bandwidth settings")
					}
				}
				id, _ := strconv.Atoi(value(row["id"]))
				version, err := InboundVersion(row)
				if err != nil {
					t.Fatal(err)
				}
				guard := func(Record) error { return nil }
				remove := func(expected string) (Record, error) {
					record, err := m.Record(serverID)
					if err != nil {
						return nil, err
					}
					return m.changeManagedCoreInbound(context.Background(), serverID, kind, record, id, expected,
						nil, nil, guard, run, true)
				}
				original := raw
				section, _, _ := relayRoutingFields(kind)
				routing := doc[section].(Record)
				rules := routing["rules"].([]any)
				routing["rules"] = append([]any{Record{"type": "field", "network": "tcp", "outboundTag": "direct"}}, rules...)
				raw, _ = json.Marshal(doc)
				if _, err := create(hash, payload); err == nil || writes != 2 {
					t.Fatal("a shadowed relay route was reused")
				}
				if _, err := remove(version); err == nil || writes != 2 {
					t.Fatal("unverified relay should not be deleted")
				}
				raw = original
				interruptWrite = true
				if _, err := remove(version); err == nil || writes != 3 {
					t.Fatal("expected interrupted relay delete")
				}
				m, err = Open(root)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := remove(version); err != nil || writes != 4 {
					t.Fatal("relay delete recovery failed", err)
				}
				retry, err := remove(strings.Repeat("0", 64))
				if err != nil || retry["alreadyMissing"] != true || writes != 4 {
					t.Fatal("confirmed named deletion should be idempotent", err)
				}
				doc = nil
				if err := json.Unmarshal(raw, &doc); err != nil || containsConfigString(doc, value(proof["outboundTag"])) ||
					containsConfigString(doc, value(row["tag"])) || len(anyRecords(doc["outbounds"])) != 1 ||
					len(anyRecords(doc["inbounds"])) != 1 {
					t.Fatal("relay cleanup left owned resources or deleted unrelated ones", err)
				}
				return
			}
			if wsTemplate(template) || grpcTemplate(template) || template == "vless-xhttp-tls" {
				id, _ := strconv.Atoi(value(row["id"]))
				version, err := InboundVersion(row)
				if err != nil {
					t.Fatal(err)
				}
				hasMeter := false
				edit := func(payload Record) (Record, error) {
					record, err := m.Record(serverID)
					if err != nil {
						return nil, err
					}
					if hasMeter {
						record["meters"] = Record{strconv.Itoa(id): row["port"]}
					}
					return m.changeManagedCoreInbound(context.Background(), serverID, kind, record, id, version, payload,
						func(old, next Record) error {
							if !sameCoreInbound(old["settings"].(Record), next["settings"].(Record)) {
								t.Fatal("edit changed client credentials")
							}
							return nil
						}, nil, run, false)
				}
				if _, err := edit(Record{"port": 443}); err == nil || writes != 2 {
					t.Fatal("occupied port was accepted")
				}
				pathField := "wsPath"
				newPath := "/go-updated"
				if grpcTemplate(template) {
					pathField, newPath = "grpcService", "go-updated"
					for _, invalid := range []string{"", "/wrong", "with space", strings.Repeat("a", 129)} {
						if _, err := edit(Record{"grpcService": invalid}); err == nil || writes != 2 {
							t.Fatal("invalid gRPC service accepted")
						}
					}
				}
				if template == "vless-xhttp-tls" {
					pathField = "xhttpPath"
					if _, err := edit(Record{"xhttpMode": "unknown"}); err == nil || writes != 2 {
						t.Fatal("unsupported XHTTP mode was accepted")
					}
				}
				patch := Record{"port": 19998, pathField: newPath}
				if template == "vless-xhttp-tls" {
					patch["xhttpMode"] = "packet-up"
				}
				hasMeter = true
				if _, err := edit(patch); err == nil || writes != 2 {
					t.Fatal("edit left a legacy meter on the old port")
				}
				hasMeter = false
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
				different := "/different"
				if grpcTemplate(template) {
					different = "different"
				}
				if _, err := edit(Record{pathField: different}); err == nil || writes != 3 {
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
				if fields[pathField] != newPath || value(fields["port"]) != "19998" {
					t.Fatal("updated settings were not persisted")
				}
				if template == "vless-xhttp-tls" && fields["xhttpMode"] != "packet-up" {
					t.Fatal("editing path and mode together lost a change")
				}
				if wsTemplate(template) || grpcTemplate(template) {
					current := replay["inbound"].(Record)
					version, err = InboundVersion(current)
					if err != nil {
						t.Fatal(err)
					}
					patch := Record{"network": "grpc", "grpcService": "switched-service"}
					if grpcTemplate(template) {
						patch = Record{"network": "tcp"}
					}
					hasMeter = true
					if _, err := edit(patch); err == nil || writes != 4 {
						t.Fatal("transport switch bypassed the associated resource guard")
					}
					hasMeter = false
					interruptWrite = true
					if _, err := edit(patch); err == nil || writes != 5 {
						t.Fatal("transport switch did not retain an interrupted intent")
					}
					m, err = Open(root)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := edit(patch); err != nil || writes != 6 {
						t.Fatal("transport switch could not resume after restart", err)
					}
					replay, err = create(hash, payload)
					if err != nil || replay["reused"] != true || writes != 6 {
						t.Fatal("transport switch lost its original creation identity", err)
					}
					stream := replay["inbound"].(Record)["streamSettings"].(Record)
					if stream["network"] != patch["network"] || stream["wsSettings"] != nil || (patch["network"] == "tcp" && stream["grpcSettings"] != nil) {
						t.Fatal("switch retained stale transport options")
					}
					current = replay["inbound"].(Record)
					version, err = InboundVersion(current)
					if err != nil {
						t.Fatal(err)
					}
					target := map[string]string{"vless": "trojan", "trojan": "vmess", "vmess": "vless"}[value(current["protocol"])]
					// Protocol conversion legitimately replaces the empty protocol settings.
					record, err := m.Record(serverID)
					if err != nil {
						t.Fatal(err)
					}
					protocolPatch := Record{"protocol": target}
					interruptWrite = true
					changeProtocol := func(record Record) (Record, error) {
						return m.changeManagedCoreInbound(context.Background(), serverID, kind, record, id, version, protocolPatch,
							func(old, next Record) error {
								if len(anyRecords(old["settings"].(Record)["clients"])) != 0 || next["protocol"] != target {
									t.Fatal("protocol switch changed a nonempty inbound")
								}
								return nil
							}, nil, run, false)
					}
					if _, err := changeProtocol(record); err == nil || writes != 7 {
						t.Fatal("protocol switch did not retain pending state")
					}
					m, err = Open(root)
					if err != nil {
						t.Fatal(err)
					}
					record, err = m.Record(serverID)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := changeProtocol(record); err != nil || writes != 8 {
						t.Fatal("protocol switch could not resume", err)
					}
					replay, err = create(hash, payload)
					if err != nil || replay["inbound"].(Record)["protocol"] != target || writes != 8 {
						t.Fatal("protocol switch lost its creation identity", err)
					}
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
					}, guard, run, false)
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

func assertStandaloneQUICUser(t *testing.T, kind, template string, row, native Record) {
	t.Helper()
	if !coreProvisionInbound(kind, row) {
		t.Fatal("created QUIC inbound does not support managed users")
	}
	if kind == "xray" {
		settings := native["settings"].(Record)
		if native["protocol"] != "hysteria" || settings["clients"] != nil || len(anyRecords(settings["users"])) != 0 {
			t.Fatal("Xray Hysteria2 must start with an empty native users list")
		}
	} else if native["type"] != template || len(anyRecords(native["users"])) != 0 {
		t.Fatal("sing-box QUIC inbound must start with an empty native users list")
	}
	client, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	row = maps.Clone(row)
	settings := maps.Clone(row["settings"].(Record))
	settings["clients"] = []any{client}
	row["settings"] = settings
	nodes, err := InboundNodes(row, Record{"host": "198.51.100.10"})
	if err != nil || len(nodes) != 1 {
		t.Fatal("could not export the new user", err)
	}
	node := nodes[0]
	uri, err := links.Export(node)
	password := client["password"]
	if kind == "xray" {
		password = client["auth"]
	}
	if err != nil || !strings.HasPrefix(uri, template+"://") || node["sni"] != "node.example.net" ||
		node["password"] != password {
		t.Fatal("export lost the QUIC user identity or certificate domain", err)
	}
	if template == "tuic" && (node["alpn"] != nil || node["uuid"] != client["id"] || strings.Contains(uri, "alpn=")) {
		t.Fatal("TUIC must export its own credentials and keep default ALPN negotiation")
	}
	if kind == "xray" {
		stream := maps.Clone(row["streamSettings"].(Record))
		stream["hysteriaSettings"] = Record{"version": 2, "auth": "shared-fallback"}
		row["streamSettings"] = stream
		if coreProvisionInbound(kind, row) {
			t.Fatal("shared fallback authentication must prevent standalone HY2 provisioning")
		}
	}
}
