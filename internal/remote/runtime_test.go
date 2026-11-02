package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"regexp"
	"strings"
	"testing"
	"time"
)

func runtimeFixture(t *testing.T) (*Panel, Record, Record) {
	t.Helper()
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/panel/api/server/getConfigJson" {
			t.Error("unexpected panel route", r.URL.Path)
		}
		json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"api": Record{"listen": "127.0.0.1:10085"}}})
	}))
	t.Cleanup(host.Close)
	base, _ := url.Parse(host.URL)
	p := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
	client := Record{"id": "8caf0efc-b4d4-4622-a70f-cc45e2ca9286", "email": "owned-user", "flow": "xtls-rprx-vision-udp443", "enable": true}
	peer := Record{"id": "8048f223-cdd9-4a0b-b488-2ca263a9a41e", "email": "peer-user", "enable": true}
	row := Record{"id": 1, "port": 24443, "tag": "inbound-24443", "protocol": "vless", "enable": true, "settings": Record{"decryption": "none", "clients": []any{peer, client}}}
	return p, row, client
}
func liveUser(client Record) string {
	raw, _ := json.Marshal(Record{"users": []any{Record{"email": client["email"], "account": Record{"id": client["id"], "flow": "xtls-rprx-vision"}}}})
	return string(raw)
}
func TestRuntimeRepairOnlyMissingOwnedUserAndVerifyOnce(t *testing.T) {
	p, row, client := runtimeFixture(t)
	before, _ := json.Marshal(row)
	live := false
	adds := 0
	script := ""
	p.run = func(ctx context.Context, command string, max int) (string, error) {
		if strings.HasPrefix(command, "for candidate") {
			return runtimeBinaries[0], nil
		}
		if strings.Contains(command, " api inbounduser ") {
			if live {
				return liveUser(client), nil
			}
			return `{"users":[{}]}`, nil
		}
		if strings.Contains(command, " api adu ") {
			adds++
			script = command
			live = true
			return "Added 1 user(s)", nil
		}
		return "", errors.New("unexpected script")
	}
	result, err := syncRuntime(context.Background(), p, row, client)
	if err != nil || result["runtimeVerified"] != true || result["runtimeRepaired"] != true {
		t.Fatal(result, err)
	}
	encoded := regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]+)'`).FindStringSubmatch(script)
	if len(encoded) != 2 {
		t.Fatal("missing protected payload")
	}
	raw, err := base64.StdEncoding.DecodeString(encoded[1])
	if err != nil {
		t.Fatal(err)
	}
	var payload Record
	if json.Unmarshal(raw, &payload) != nil {
		t.Fatal("invalid payload")
	}
	inbound := payload["inbounds"].([]any)[0].(map[string]any)
	clients := inbound["settings"].(map[string]any)["clients"].([]any)
	if len(clients) != 1 || clients[0].(map[string]any)["id"] != client["id"] || clients[0].(map[string]any)["flow"] != "xtls-rprx-vision" {
		t.Fatal("payload contains peer or wrong flow", clients)
	}
	if strings.Contains(string(raw), "peer-user") || strings.Contains(script, "restart") || strings.Contains(script, " api rmu ") {
		t.Fatal("repair touches another user or service")
	}
	after, _ := json.Marshal(row)
	if string(before) != string(after) {
		t.Fatal("repair changed panel row")
	}
	if binary, err := exec.LookPath("bash"); err == nil {
		cmd := exec.Command(binary, "-n")
		cmd.Stdin = strings.NewReader(script)
		if output, e := cmd.CombinedOutput(); e != nil {
			t.Fatal(string(output), e)
		}
	} else {
		t.Log("bash unavailable; shell syntax check not run")
	}
	result, err = syncRuntime(context.Background(), p, row, client)
	if err != nil || result["runtimeRepaired"] != false || adds != 1 {
		t.Fatal("repeated repair", result, err)
	}
}
func TestRuntimeMismatchUnsupportedAndInterruptedWrite(t *testing.T) {
	for _, mode := range []string{"mismatch", "zero-add", "unsupported", "offline", "ambiguous", "opaque"} {
		t.Run(mode, func(t *testing.T) {
			p, row, client := runtimeFixture(t)
			adds := 0
			p.run = func(ctx context.Context, script string, max int) (string, error) {
				if strings.HasPrefix(script, "for candidate") {
					return runtimeBinaries[0], nil
				}
				if strings.Contains(script, " api adu ") {
					adds++
					if mode == "ambiguous" {
						return "", errors.New("SSH interrupted")
					}
					return "Added 0 user(s)", nil
				}
				switch mode {
				case "mismatch":
					return `{"users":[{"email":"owned-user","account":{"id":"8048f223-cdd9-4a0b-b488-2ca263a9a41e","flow":"xtls-rprx-vision"}}]}`, nil
				case "unsupported":
					return "rpc error: Unimplemented", errors.New("exit 1")
				case "offline":
					return "connection refused", errors.New("exit 1")
				case "opaque":
					return `{"users":[{"email":"owned-user","account":"opaque-blob"}]}`, nil
				}
				return `{"users":[]}`, nil
			}
			result, err := syncRuntime(context.Background(), p, row, client)
			if mode == "unsupported" || mode == "opaque" {
				if err != nil || result["runtimeVerified"] != nil || adds != 0 {
					t.Fatal(result, err, adds)
				}
			} else {
				if err == nil {
					t.Fatal("unverified runtime reported success", mode)
				}
				expected := 0
				if mode == "zero-add" || mode == "ambiguous" {
					expected = 1
				}
				if adds != expected {
					t.Fatal("mutation replayed or conflicting user replaced", adds)
				}
			}
		})
	}
}
func TestRuntimeAuthorizationLimitsAndLoopbackAddresses(t *testing.T) {
	for _, change := range []Record{{"enable": false}, {"expiryTime": 1}, {"total": 1, "up": 1}, {"clientStats": []any{Record{"email": "owned-user", "enable": false}}}, {"clientStats": []any{Record{"email": "owned-user", "total": 1, "up": 1}}}, {"clientStats": []any{Record{"email": "owned-user"}, Record{"email": "owned-user"}}}} {
		p, row, client := runtimeFixture(t)
		for k, v := range change {
			row[k] = v
		}
		called := false
		p.run = func(context.Context, string, int) (string, error) { called = true; return "", nil }
		if _, err := syncRuntime(context.Background(), p, row, client); err == nil || called {
			t.Fatal("remote restriction bypassed", change)
		}
	}
	for _, address := range []string{"198.51.100.1:10085", "localhost:10085", "0.0.0.0:10085", "127.0.0.1:0", "[fe80::1%eth0]:1234", "127.0.0.1:99999"} {
		if runtimeAddress(Record{"api": Record{"listen": address}}) != "" {
			t.Fatal("non-loopback API accepted", address)
		}
	}
	if address := runtimeAddress(Record{"api": Record{"tag": "api"}, "inbounds": []any{Record{"tag": "api", "listen": "::", "port": 1234}}}); address != "[::1]:1234" {
		t.Fatal(address)
	}
	_, row, client := runtimeFixture(t)
	client["expiryTime"] = time.Now().Add(-time.Hour).UnixMilli()
	if err := runtimeAuthorized(row, client, time.Now()); err == nil {
		t.Fatal("expired client accepted")
	}
}
func TestRuntimeStatusRejectsMalformedAndNormalizesUUID(t *testing.T) {
	client := Record{"email": "owned", "id": "8caf0efc-b4d4-4622-a70f-cc45e2ca9286", "flow": "xtls-rprx-vision-udp443"}
	status, err := runtimeStatus(`{"users":[{"email":"owned","account":{"id":"8CAF0EFCB4D44622A70FCC45E2CA9286","flow":"xtls-rprx-vision"}}]}`, "vless", client)
	if err != nil || status != "present" {
		t.Fatal(status, err)
	}
	for _, text := range []string{`{}`, `{"users":null}`, `{"users":[]} {}`, `{"users":[{"email":"owned","account":{"id":"bad"}}]}`, `{"users":[{"email":"owned","account":{"id":"8CAF0EFCB4D44622A70FCC45E2CA9286","flow":true}}]}`} {
		if _, err := runtimeStatus(text, "vless", client); err == nil {
			t.Fatal("malformed status accepted", text)
		}
	}
}

func TestRuntimeConfigFailuresAndPublicAPIAreNotUsedForRepair(t *testing.T) {
	for _, code := range []int{200, 404, 403, 500} {
		t.Run(http.StatusText(code), func(t *testing.T) {
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(code)
				if code == 200 {
					json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"api": Record{"listen": "198.51.100.1:10085"}}})
				}
			}))
			defer host.Close()
			base, _ := url.Parse(host.URL)
			panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
			called := false
			panel.run = func(context.Context, string, int) (string, error) { called = true; return "", nil }
			_, row, client := runtimeFixture(t)
			result, err := syncRuntime(context.Background(), panel, row, client)
			if called {
				t.Fatal("invalid or unavailable runtime config reached SSH mutation")
			}
			if code == 404 || code == 200 {
				if err != nil || result["runtimeVerified"] != nil {
					t.Fatal(result, err)
				}
			} else if err == nil {
				t.Fatal("authentication/server error treated as unsupported")
			}
		})
	}
}

func TestHY2RuntimeAuthRepair(t *testing.T) {
	for _, protocol := range []string{"hysteria", "hysteria2"} {
		t.Run(protocol, func(t *testing.T) {
			panel, row, _ := runtimeFixture(t)
			row["protocol"] = protocol
			row["settings"] = Record{"version": 2, "clients": []any{}}
			client := Record{"email": "hy2-owned", "enable": true}
			if protocol == "hysteria" {
				client["auth"] = "auth:+@ password"
			} else {
				client["password"] = "auth:+@ password"
			}
			live, adds := false, 0
			panel.run = func(ctx context.Context, script string, max int) (string, error) {
				if strings.HasPrefix(script, "for candidate") {
					return runtimeBinaries[0], nil
				}
				if strings.Contains(script, " api adu ") {
					encoded := regexp.MustCompile(`printf '%s' '([A-Za-z0-9+/=]+)'`).FindStringSubmatch(script)
					raw, _ := base64.StdEncoding.DecodeString(encoded[1])
					var payload Record
					json.Unmarshal(raw, &payload)
					inbound := payload["inbounds"].([]any)[0].(map[string]any)
					users := inbound["settings"].(map[string]any)["clients"].([]any)
					if inbound["protocol"] != "hysteria" || len(users) != 1 || users[0].(map[string]any)["auth"] != "auth:+@ password" {
						t.Error("HY2 runtime auth lost", inbound)
					}
					live = true
					adds++
					return "Added 1 user", nil
				}
				if live {
					return `{"users":[{"email":"hy2-owned","account":{"auth":"auth:+@ password"}}]}`, nil
				}
				return `{"users":[]}`, nil
			}
			result, err := syncRuntime(context.Background(), panel, row, client)
			if err != nil || result["runtimeVerified"] != true || adds != 1 {
				t.Fatal(result, err)
			}
			result, err = syncRuntime(context.Background(), panel, row, client)
			if err != nil || result["runtimeRepaired"] != false || adds != 1 {
				t.Fatal("HY2 repair repeated", result, err)
			}
		})
	}
}
