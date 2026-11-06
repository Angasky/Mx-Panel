package remote

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInboundTemplatesNoUnownedCredentials(t *testing.T) {
	for _, name := range []string{"vless-reality", "vmess-tcp", "vless-tcp-tls", "vmess-tcp-tls", "trojan-tls", "trojan-ws-tls", "trojan-grpc-tls", "vless-ws-tls", "vmess-ws-tls", "hysteria2"} {
		t.Run(name, func(t *testing.T) {
			payload := Record{"template": name, "serverName": "node.example.com", "certFile": "/etc/cert/fullchain.pem", "keyFile": "/etc/cert/key.pem", "path": "/vpn"}
			row, err := buildInboundTemplate(payload, "1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}
			port, _ := parsedPort(row["port"], 0)
			if port <= 20000 || port > 65535 {
				t.Fatal("bad random port", port)
			}
			settings := row["settings"].(Record)
			if len(settings["clients"].([]any)) != 0 {
				t.Fatal("created unowned credential")
			}
			user, err := NewUser(row)
			if err != nil {
				t.Fatal(err)
			}
			if name == "vless-reality" {
				if user["flow"] != "xtls-rprx-vision" {
					t.Fatal(user)
				}
				reality := row["streamSettings"].(Record)["realitySettings"].(Record)
				raw, _ := base64.RawURLEncoding.DecodeString(value(reality["privateKey"]))
				private, err := ecdh.X25519().NewPrivateKey(raw)
				if err != nil {
					t.Fatal(err)
				}
				if value(reality["settings"].(Record)["publicKey"]) != base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()) || reality["target"] != "1.1.1.1:443" {
					t.Fatal("Reality key/target mismatch")
				}
			}
			if name == "hysteria2" {
				if row["protocol"] != "hysteria" || settings["version"] != 2 || value(user["auth"]) == "" {
					t.Fatal("HY2 panel/auth mapping lost")
				}
			}
		})
	}
	for _, payload := range []Record{
		{"template": "tuic"}, {"template": "shadowsocks"}, {"template": "vmess-tcp", "port": true}, {"template": "vmess-tcp", "port": "0"}, {"inbound": Record{}, "template": "vmess-tcp"},
		{"template": "hysteria2", "serverName": "node.example.com", "certFile": "/etc/../key", "keyFile": "/key"},
	} {
		if _, err := buildInboundTemplate(payload, "1.1.1.1"); err == nil {
			t.Fatal("invalid template accepted", payload)
		}
	}
}

func createPanelFixture(t *testing.T) (*Panel, *[]Record, *int, *string) {
	t.Helper()
	rows := []Record{}
	writes := 0
	mode := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/list") {
			if mode == "malformed" {
				json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{}})
				return
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": rows})
			return
		}
		if !strings.HasSuffix(r.URL.Path, "/add") {
			t.Error("unexpected path", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		writes++
		if mode == "unauthorized" {
			w.WriteHeader(401)
			return
		}
		r.ParseForm()
		row := Record{"id": json.Number("7"), "tag": "inbound-24001"}
		for k, vs := range r.Form {
			v := vs[0]
			switch k {
			case "port", "up", "down", "total", "expiryTime":
				row[k] = json.Number(v)
			case "enable":
				row[k] = v == "true"
			case "settings", "streamSettings", "sniffing":
				row[k] = v
			default:
				row[k] = v
			}
		}
		if mode != "not-applied" {
			rows = append(rows, row)
		}
		if mode == "disconnect" {
			connection, _, _ := w.(http.Hijacker).Hijack()
			connection.Close()
			return
		}
		json.NewEncoder(w).Encode(Record{"success": true, "obj": row})
	}))
	t.Cleanup(server.Close)
	base, _ := url.Parse(server.URL + "/")
	return newPanel(base, server.Client().Transport, Record{}, "", "fixture-token", NewPanelSession()), &rows, &writes, &mode
}
func createEntry(t *testing.T) Record {
	t.Helper()
	desired, err := buildInboundTemplate(Record{"template": "vmess-tcp", "port": 24001}, "")
	if err != nil {
		t.Fatal(err)
	}
	return Record{"serverId": "s", "scope": "clash", "revision": "fixture", "requestHash": "request", "status": "prepared", "desired": desired}
}

func TestInboundCreateDisconnectRestartReconcilesWithoutReplay(t *testing.T) {
	root := t.TempDir()
	manager, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	p, _, writes, mode := createPanelFixture(t)
	*mode = "disconnect"
	entry := createEntry(t)
	persist := func(e Record) error { return manager.persistCreate("fixture", e) }
	if err = persist(entry); err != nil {
		t.Fatal(err)
	}
	if _, err = createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp", "port": 24001}, entry, persist); err == nil {
		t.Fatal("disconnect reported success")
	}
	manager, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := manager.loadCreate("fixture")
	if err != nil || saved["status"] != "sent" {
		t.Fatal(saved, err)
	}
	desired, err := manager.OpenUser(value(saved["sealedDesired"]))
	if err != nil {
		t.Fatal(err)
	}
	saved["desired"] = desired
	*mode = ""
	result, err := createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp", "port": 24001}, saved, persist)
	if err != nil || *writes != 1 || result["reused"] != true {
		t.Fatal(result, err, *writes)
	}
	if _, err = createPanelInbound(context.Background(), p, Record{}, Record{}, saved, persist); err != nil || *writes != 1 {
		t.Fatal("confirmed retry rewrote inbound", err)
	}
}

func TestInboundCreateNeverReplaysOrWritesBeforeDurableIntent(t *testing.T) {
	for _, mode := range []string{"unauthorized", "not-applied", "malformed"} {
		t.Run(mode, func(t *testing.T) {
			p, _, writes, behavior := createPanelFixture(t)
			*behavior = mode
			entry := createEntry(t)
			persist := func(Record) error { return nil }
			_, err := createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp", "port": 24001}, entry, persist)
			if err == nil {
				t.Fatal("unconfirmed write succeeded")
			}
			_, err = createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp", "port": 24001}, entry, persist)
			want := 1
			if mode == "malformed" {
				want = 0
			}
			if err == nil || *writes != want {
				t.Fatal("request replayed", err, *writes)
			}
		})
	}
	p, _, writes, _ := createPanelFixture(t)
	entry := createEntry(t)
	_, err := createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp"}, entry, func(Record) error { return errors.New("disk full") })
	if err == nil || *writes != 0 {
		t.Fatal("granted before durable intent", err, *writes)
	}
}

func TestInboundCreateCollisionAndConfirmedIDReuse(t *testing.T) {
	p, rows, writes, _ := createPanelFixture(t)
	entry := createEntry(t)
	*rows = []Record{{"id": 2, "port": 24001, "protocol": "vmess", "remark": "existing"}}
	_, err := createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp", "port": 24001}, entry, func(Record) error { return nil })
	if err == nil || *writes != 0 {
		t.Fatal("used explicit port", err)
	}
	entry = createEntry(t)
	result, err := createPanelInbound(context.Background(), p, Record{}, Record{"template": "vmess-tcp"}, entry, func(Record) error { return nil })
	if err != nil || *writes != 1 || value(result["inbound"].(Record)["port"]) == "24001" {
		t.Fatal(result, err)
	}
	(*rows)[1]["port"] = 25001
	if _, err = createPanelInbound(context.Background(), p, Record{}, Record{}, entry, func(Record) error { return nil }); err == nil || *writes != 1 {
		t.Fatal("reused ID accepted")
	}
}

func TestInboundJournalSealsPrivateKeyAndRejectsOperationReuse(t *testing.T) {
	manager, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entry := createEntry(t)
	entry["desired"].(Record)["private-example"] = "fixture-private-secret"
	if err = manager.persistCreate("op", entry); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(filepath.Join(manager.root, "inbound-creates.json"))
	if strings.Contains(string(raw), "fixture-private-secret") || strings.Contains(string(raw), "private-example") {
		t.Fatal("plaintext desired config persisted")
	}
	other := createEntry(t)
	other["serverId"] = "other"
	if err = manager.persistCreate("op", other); err == nil {
		t.Fatal("operation reused across servers")
	}
	payload := Record{"operationId": strings.Repeat("a", 32), "template": "vmess-tcp"}
	key, a, err := createRequestIdentity("clash", payload)
	if err != nil {
		t.Fatal(err)
	}
	payload["port"] = 24001
	key2, b, _ := createRequestIdentity("clash", payload)
	if key != key2 || a == b {
		t.Fatal("operation identity does not detect changed request")
	}
	if _, _, err = createRequestIdentity("clash", Record{}); err == nil {
		t.Fatal("missing operation accepted")
	}
}

func TestRealityCreationRequiresFreshServerBoundScan(t *testing.T) {
	manager, id := certificateFixture(t)
	record, _ := manager.Record(id)
	payload := Record{"template": "vless-reality", "serverName": "node.example.com", "sniAddress": "1.1.1.1"}
	if _, _, err := manager.templatePayload(id, record, payload); err == nil {
		t.Fatal("unverified SNI accepted")
	}
	scanner := manager.sniState()
	key := sniCacheKey{id, certificateRevision(record), "node.example.com", "1.1.1.1"}
	scanner.remember(key, true)
	_, address, err := manager.templatePayload(id, record, payload)
	if err != nil || address != "1.1.1.1" {
		t.Fatal(address, err)
	}
	scanner.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if _, _, err = manager.templatePayload(id, record, payload); err == nil {
		t.Fatal("expired scan accepted")
	}
}

func TestCertificateValidationPrecedesInboundWrite(t *testing.T) {
	p, _, writes, _ := createPanelFixture(t)
	payload := Record{"template": "hysteria2", "serverName": "node.example.com", "certFile": "/etc/fullchain.pem", "keyFile": "/etc/key.pem", "port": 24001}
	desired, err := buildInboundTemplate(payload, "")
	if err != nil {
		t.Fatal(err)
	}
	entry := createEntry(t)
	entry["desired"] = desired
	p.run = func(ctx context.Context, script string, limit int) (string, error) {
		if strings.Contains(script, "python") || !strings.Contains(script, "-checkhost") || !strings.Contains(script, "-passin pass:") {
			t.Error("bad certificate script")
		}
		return "", errors.New("mismatch")
	}
	_, err = createPanelInbound(context.Background(), p, Record{}, payload, entry, func(Record) error { return nil })
	if err == nil || *writes != 0 || entry["status"] != "prepared" {
		t.Fatal("bad certificate created inbound", err)
	}
	p.run = func(context.Context, string, int) (string, error) { return "MXIOC_CERTIFICATE_OK\n", nil }
	if _, err = createPanelInbound(context.Background(), p, Record{}, payload, entry, func(Record) error { return nil }); err != nil || *writes != 1 {
		t.Fatal(err, *writes)
	}
}

func TestCreateJournalRejectsChangedPanelBeforeConnecting(t *testing.T) {
	manager, server := certificateFixture(t)
	record, _ := manager.Record(server)
	payload := Record{"operationId": strings.Repeat("a", 32), "template": "vmess-tcp"}
	key, hash, err := createRequestIdentity("clash", payload)
	if err != nil {
		t.Fatal(err)
	}
	entry := createEntry(t)
	entry["serverId"] = server
	entry["revision"] = createServerRevision(record)
	entry["requestHash"] = hash
	if err = manager.persistCreate(key, entry); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.Save(Record{"id": server, "panelAddress": "https://other.example.com:13145/path/"}); err != nil {
		t.Fatal(err)
	}
	if _, err = manager.CreateInbound(context.Background(), server, "clash", payload); err == nil || !strings.Contains(err.Error(), "服务器身份已变化") {
		t.Fatal("changed panel accepted", err)
	}
}
