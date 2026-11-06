package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func startSSFixtureCore(t *testing.T, ctx context.Context, binary, kind string, config Record, port int) (func(), *capture) {
	t.Helper()
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"run", "-config", file}
	if kind == "sing-box" {
		args = []string{"run", "-c", file}
	}
	if kind == "mihomo" {
		args = []string{"-d", filepath.Dir(file), "-f", file}
	}
	command := exec.CommandContext(ctx, binary, args...)
	log := &capture{limit: 64 << 10}
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	stop := func() { command.Process.Kill(); command.Wait() }
	t.Cleanup(func() {
		if command.ProcessState == nil {
			stop()
		}
	})
	until := time.Now().Add(3 * time.Second)
	for time.Now().Before(until) {
		connection, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", value(port)), 50*time.Millisecond)
		if err == nil {
			connection.Close()
			return stop, log
		}
		time.Sleep(20 * time.Millisecond)
	}
	output, _ := log.result()
	t.Fatal("SS fixture core failed to listen", output)
	return nil, nil
}

func TestSS2022MultiUserExportWithRealCores(t *testing.T) {
	testShadowsocksUsersWithRealCores(t, []string{"2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "aes-128-gcm"})
}

func TestManagedSSAEADUsersWithRealCore(t *testing.T) {
	testShadowsocksUsersWithRealCores(t, []string{"managed:aes-128-gcm", "managed:aes-256-gcm", "managed:chacha20-ietf-poly1305"})
}

func testShadowsocksUsersWithRealCores(t *testing.T, methods []string) {
	xray := os.Getenv("MXIOC_TEST_XRAY")
	if xray == "" {
		t.Skip("set MXIOC_TEST_XRAY for real SS2022 export verification")
	}
	port := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	for _, method := range methods {
		caseName := method
		managedAEAD := strings.HasPrefix(method, "managed:")
		method = strings.TrimPrefix(method, "managed:")
		for _, kind := range []string{"xray", "sing-box"} {
			if kind == "sing-box" && !strings.HasPrefix(method, "2022-") {
				continue // sing-box classic AEAD is not a multi-user inbound.
			}
			t.Run(caseName+"/"+kind, func(t *testing.T) {
				binary := xray
				if kind == "sing-box" {
					binary = os.Getenv("MXIOC_TEST_SING_BOX")
					if binary == "" {
						t.Skip("set MXIOC_TEST_SING_BOX for sing-box SS2022 verification")
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 75*time.Second)
				defer cancel()
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ss2022-user-proof") }))
				defer target.Close()
				row := ss2022Fixture(method)
				if !strings.HasPrefix(method, "2022-") {
					for _, client := range anyRecords(row["settings"].(Record)["clients"]) {
						client["method"] = method
					}
					anyRecords(row["settings"].(Record)["clients"])[1]["method"] = "aes-256-gcm"
				}
				modern := strings.HasPrefix(method, "2022-")
				withStats := modern || managedAEAD
				if modern || managedAEAD {
					template := "ss2022-aes-128"
					if method == "2022-blake3-aes-256-gcm" {
						template = "ss2022-aes-256"
					}
					if managedAEAD {
						aeadTemplate := "ss-" + method
						if method == "chacha20-ietf-poly1305" {
							aeadTemplate = "ss-chacha20-poly1305"
						}
						row = managedSSAEADFixture(t, aeadTemplate)
					} else {
						row = managedSS2022Fixture(t, template)
					}
					users := []any{}
					for _, name := range []string{"first", "second", "disabled"} {
						user, err := NewUser(row)
						if err != nil {
							t.Fatal(err)
						}
						user["email"] = name
						if name == "disabled" {
							user["enable"] = false
						}
						users = append(users, user)
					}
					row["settings"].(Record)["clients"] = users
				}
				row["port"], row["listen"], row["id"], row["tag"] = port(), "127.0.0.1", 1, "mxioc-inbound-1"
				apiAddress := "127.0.0.1:" + value(port())
				var serverDoc Record
				nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
				if err != nil || len(nodes) != 2 {
					t.Fatal(err)
				}
				out := Record{"protocol": "freedom", "settings": Record{"finalRules": []any{Record{"action": "allow", "network": "tcp", "ip": []any{"127.0.0.1/32"}}}}}
				if kind == "sing-box" {
					out = Record{"type": "direct", "tag": "direct"}
				}
				startServer := func() (func(), *capture) {
					native, err := legacyNativeInbound(kind, row)
					if err != nil {
						t.Fatal(err)
					}
					serverDoc = Record{"inbounds": []any{native}, "outbounds": []any{out}}
					if withStats {
						serverDoc, err = planCoreStats(kind, serverDoc)
						if err != nil {
							t.Fatal(err)
						}
						api := serverDoc["api"]
						if kind == "sing-box" {
							api = serverDoc["experimental"].(Record)["v2ray_api"]
						}
						api.(Record)["listen"] = apiAddress
						if kind == "sing-box" {
							api.(Record)["stats"].(Record)["users"] = []any{"first", "second"}
						}
					}
					return startSSFixtureCore(t, ctx, binary, kind, serverDoc, row["port"].(int))
				}
				stopServer, serverLog := startServer()
				request := func(node Record, allowed bool) {
					t.Helper()
					uri, err := links.Export(node)
					if err != nil {
						t.Fatal(err)
					}
					parsed, err := links.Parse(uri)
					if err != nil {
						t.Fatal(err)
					}
					outbound, err := NodeOutbound(parsed, "ss2022")
					if err != nil {
						t.Fatal(err)
					}
					outbound["settings"].(Record)["servers"].([]any)[0].(Record)["address"] = "127.0.0.1"
					socks := port()
					stopClient, clientLog := startSSFixtureCore(t, ctx, xray, "xray", Record{"inbounds": []any{Record{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": Record{"auth": "noauth"}}}, "outbounds": []any{outbound}}, socks)
					proxy, _ := url.Parse("socks5://127.0.0.1:" + value(socks))
					transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
					response, requestErr := (&http.Client{Transport: transport, Timeout: 1200 * time.Millisecond}).Get(target.URL)
					var body []byte
					if response != nil {
						body, _ = io.ReadAll(response.Body)
						response.Body.Close()
					}
					transport.CloseIdleConnections()
					stopClient()
					if (requestErr == nil && string(body) == "ss2022-user-proof") != allowed {
						a, _ := serverLog.result()
						b, _ := clientLog.result()
						t.Fatal("SS2022 user export/authentication mismatch", allowed, requestErr, a, b)
					}
				}
				readCounts := func() map[string]coreTraffic {
					t.Helper()
					for attempt := 0; attempt < 40; attempt++ {
						var output []byte
						var err error
						if kind == "sing-box" {
							raw, queryErr := querySingStats(ctx, apiAddress, (&net.Dialer{}).DialContext)
							output, err = []byte(raw), queryErr
						} else {
							output, err = exec.CommandContext(ctx, xray, "api", "statsquery", "--server="+apiAddress, "--pattern=user>>>").Output()
						}
						if err == nil {
							counters, err := parseCoreCounters(string(output))
							if err != nil {
								t.Fatal("invalid native counter reply", err)
							}
							return counters
						}
						time.Sleep(25 * time.Millisecond)
					}
					t.Fatal("native stats API not available")
					return nil
				}
				request(nodes[0], true)
				var first coreTraffic
				if withStats {
					counts := readCounts()
					first = counts["first"]
					if first.up <= 0 || first.down <= 0 || counts["second"] != (coreTraffic{}) {
						t.Fatal("first user counters not isolated", counts)
					}
				}
				request(nodes[1], true)
				if withStats {
					counts := readCounts()
					if counts["first"] != first || counts["second"].up <= 0 || counts["second"].down <= 0 {
						t.Fatal("second user counters not isolated", counts)
					}
				}
				invalid := Record{}
				for key, v := range nodes[0] {
					invalid[key] = v
				}
				settings := row["settings"].(Record)
				invalid["password"] = settings["password"]
				request(invalid, false) // Root key alone must not authenticate in multi-user mode.
				if managedAEAD {
					unknown, err := NewUser(row)
					if err != nil {
						t.Fatal(err)
					}
					invalid["password"] = unknown["password"]
				} else {
					key, _ := base64.StdEncoding.DecodeString(value(settings["password"]))
					key[0] ^= 0xff
					invalid["password"] = value(settings["password"]) + ":" + base64.StdEncoding.EncodeToString(key)
				}
				request(invalid, false)
				stopServer()
				if modern || managedAEAD {
					users := anyRecords(settings["clients"])
					apply := func(operation string, user Record) {
						t.Helper()
						binding := bindingFor(t, row, user)
						binding["inboundId"] = row["id"]
						if operation == "resume" {
							binding["monthlyPaused"] = true
						}
						next, rows, err := planCoreUserChange(kind, operation, legacyCoreState{Inbounds: []Record{row}}, serverDoc, binding, false)
						if err != nil || next == nil || len(rows) != 1 {
							t.Fatal("SS2022 lifecycle failed", operation, err)
						}
						row, serverDoc = rows[0], next
					}
					apply("remove", users[0])
					stopServer, serverLog = startServer()
					request(nodes[0], false)
					request(nodes[1], true)
					stopServer()
					apply("pause", users[1])
					if exported, err := InboundNodes(row, Record{}); err != nil || len(exported) != 0 {
						t.Fatal("guard leaked into links", err)
					}
					stopServer, serverLog = startServer()
					request(nodes[0], false)
					request(nodes[1], false)
					invalid["password"] = settings["password"]
					request(invalid, false)
					stopServer()
					apply("resume", anyRecords(row["settings"].(Record)["clients"])[0])
					stopServer, serverLog = startServer()
					request(nodes[1], true)
					stopServer()
					apply("remove", anyRecords(row["settings"].(Record)["clients"])[0])
					stopServer, serverLog = startServer()
					request(nodes[0], false)
					request(nodes[1], false)
					request(invalid, false)
					stopServer()
				} else {
					settings["clients"] = []any{anyRecords(settings["clients"])[1]}
					stopServer, serverLog = startServer()
					request(nodes[0], false)
					request(nodes[1], true)
					stopServer()
				}
			})
		}
	}
}
