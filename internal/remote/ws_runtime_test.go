package remote

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

// Optional real-core regression: use the production template, native mapping,
// subscription URI and outbound conversion, with all traffic on loopback.
func TestTLSStreamTemplatesWithRealCores(t *testing.T) {
	xray := os.Getenv("MXIOC_TEST_XRAY")
	if xray == "" {
		t.Skip("set MXIOC_TEST_XRAY for real TLS transport verification")
	}
	port := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	for _, template := range []string{"vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls", "vless-tcp-tls", "vmess-tcp-tls", "trojan-tls", "vless-grpc-tls", "vmess-grpc-tls", "trojan-grpc-tls", "vless-reality"} {
		for _, kind := range []string{"xray", "sing-box"} {
			t.Run(template+"/"+kind, func(t *testing.T) {
				binary := xray
				if kind == "sing-box" {
					binary = os.Getenv("MXIOC_TEST_SING_BOX")
					if binary == "" {
						t.Skip("set MXIOC_TEST_SING_BOX for sing-box verification")
					}
				}
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, "owned-tls-transport-proof")
				}))
				defer target.Close()
				cert, key := templateTestCertificate(t, "node.example.com", false)
				row, err := buildInboundTemplate(Record{"template": template, "port": port(), "serverName": "node.example.com",
					"certFile": "/fixture/cert", "keyFile": "/fixture/key", "path": "/owned-ws"}, "1.1.1.1")
				if err != nil {
					t.Fatal(err)
				}
				if wsTemplate(template) || grpcTemplate(template) {
					row["goCreateKey"] = "fixture"
					row, err = prepareManagedCoreEdit(row, Record{"network": "tcp"})
					if err == nil {
						patch := Record{"network": "ws", "wsPath": "/owned-ws"}
						if grpcTemplate(template) {
							patch = Record{"network": "grpc", "grpcService": "vpn"}
						}
						row, err = prepareManagedCoreEdit(row, patch)
					}
					if err != nil {
						t.Fatal("transport switch failed before native test", err)
					}
				}
				row["tag"], row["listen"] = "fixture", "127.0.0.1"
				if template != "vless-reality" {
					row["goCreateKey"] = "fixture"
					target := map[string]string{"vless": "trojan", "trojan": "vmess", "vmess": "vless"}[value(row["protocol"])]
					row, err = prepareManagedCoreEdit(row, Record{"protocol": target})
					if err != nil {
						t.Fatal("protocol switch failed before native test", err)
					}
				}
				stream := row["streamSettings"].(Record)
				if template == "vless-reality" {
					pair, err := tls.LoadX509KeyPair(cert, key)
					if err != nil {
						t.Fatal(err)
					}
					// Replace only the scanned destination with a local TLS 1.3 target.
					fallback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
					fallback.Config.ErrorLog = log.New(io.Discard, "", 0) // Invalid Reality probes intentionally reach the TLS target.
					fallback.EnableHTTP2 = true
					fallback.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, CurvePreferences: []tls.CurveID{tls.X25519}}
					fallback.StartTLS()
					defer fallback.Close()
					stream["realitySettings"].(Record)["target"] = fallback.Listener.Addr().String()
				} else {
					stream["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "keyFile": key}}
				}
				user, err := NewUser(row)
				if err != nil {
					t.Fatal(err)
				}
				row["settings"].(Record)["clients"] = []any{user}
				native, err := legacyNativeInbound(kind, row)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
				defer cancel()
				start := func(binary, kind string, config Record, listen int) (func(), *capture) {
					data, err := json.Marshal(config)
					if err != nil {
						t.Fatal(err)
					}
					file := filepath.Join(t.TempDir(), "config.json")
					if err := os.WriteFile(file, data, 0600); err != nil {
						t.Fatal(err)
					}
					args := []string{"run", "-config", file}
					if kind == "sing-box" {
						args = []string{"run", "-c", file}
					}
					command := exec.CommandContext(ctx, binary, args...)
					output := &capture{limit: 64 << 10}
					command.Stdout, command.Stderr = output, output
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
						conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", value(listen)), 50*time.Millisecond)
						if err == nil {
							conn.Close()
							return stop, output
						}
						time.Sleep(20 * time.Millisecond)
					}
					log, _ := output.result()
					t.Fatal("test core did not listen", log)
					return nil, nil
				}
				serverOut := Record{"protocol": "freedom", "settings": Record{"finalRules": []any{Record{"action": "allow", "network": "tcp", "ip": []any{"127.0.0.1/32"}}}}}
				if kind == "sing-box" {
					serverOut = Record{"type": "direct", "tag": "direct"}
				}
				_, serverLog := start(binary, kind, Record{"inbounds": []any{native}, "outbounds": []any{serverOut}}, row["port"].(int))
				nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
				if err != nil || len(nodes) != 1 {
					t.Fatal("cannot export owned user", err)
				}
				uri, err := links.Export(nodes[0])
				if err != nil {
					t.Fatal(err)
				}
				scenarios := []string{"owned", "wrong-user"}
				if template == "vless-reality" {
					scenarios = append(scenarios, "wrong-short-id")
				} else if !tcpTLSTemplate(template) {
					scenarios = append(scenarios, "wrong-path")
				}
				for _, scenario := range scenarios {
					node, err := links.Parse(uri)
					if err != nil {
						t.Fatal(err)
					}
					if scenario == "wrong-path" {
						if grpcTemplate(template) {
							node["grpc-opts"].(Record)["grpc-service-name"] = "wrong-service"
						} else {
							node["ws-opts"].(Record)["path"] = "/wrong-path"
						}
					}
					if scenario == "wrong-user" {
						other, err := NewUser(row)
						if err != nil {
							t.Fatal(err)
						}
						if row["protocol"] == "trojan" {
							node["password"] = other["password"]
						} else {
							node["uuid"] = other["id"]
						}
					}
					if scenario == "wrong-short-id" {
						node["reality-opts"].(Record)["short-id"] = "ffffffffffffffff"
					}
					out, err := NodeOutbound(node, "proxy")
					if err != nil {
						t.Fatal(err)
					}
					settings := out["settings"].(Record)
					if row["protocol"] == "vmess" {
						settings["vnext"].([]any)[0].(Record)["address"] = "127.0.0.1"
					} else if row["protocol"] == "trojan" {
						settings["servers"].([]any)[0].(Record)["address"] = "127.0.0.1"
					} else {
						settings["address"] = "127.0.0.1"
					}
					// Trust only this test's local certificate, keeping verification on.
					if template != "vless-reality" {
						out["streamSettings"].(Record)["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "usage": "verify"}}
					}
					socks := port()
					stop, clientLog := start(xray, "xray", Record{"inbounds": []any{Record{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": Record{"auth": "noauth"}}}, "outbounds": []any{out}}, socks)
					proxy, _ := url.Parse("socks5://127.0.0.1:" + value(socks))
					transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
					response, requestErr := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL)
					var body []byte
					if response != nil {
						body, _ = io.ReadAll(response.Body)
						response.Body.Close()
					}
					transport.CloseIdleConnections()
					stop()
					passed := requestErr == nil && string(body) == "owned-tls-transport-proof"
					if passed != (scenario == "owned") {
						a, _ := serverLog.result()
						b, _ := clientLog.result()
						t.Fatal("TLS transport path or user verification failed", scenario, requestErr, a, b)
					}
				}
			})
		}
	}
}
