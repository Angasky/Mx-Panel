package remote

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

// Exercise the production template -> URI -> client mapping -> authenticated
// traffic -> counter query and revocation chain, without remote infrastructure.
func TestSingBoxProtocolsAccountingAndRevocationWithRealCore(t *testing.T) {
	testCoreAccounting(t, "sing-box", false, []string{"vmess-tcp", "vless-tcp-tls", "vmess-tcp-tls", "trojan-tls", "vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls", "vless-grpc-tls", "vmess-grpc-tls", "trojan-grpc-tls", "hysteria2", "tuic"})
}

func TestSingBoxQUICUDPAccountingAndRevocationWithRealCore(t *testing.T) {
	testCoreAccounting(t, "sing-box", true, []string{"hysteria2", "tuic"})
}

func TestSingBoxRealityAccountingAndRevocationWithRealCore(t *testing.T) {
	testCoreAccounting(t, "sing-box", false, []string{"vless-reality"})
}

func TestXrayRealityAccountingAndRevocationWithRealCore(t *testing.T) {
	testCoreAccounting(t, "xray", false, []string{"vless-reality"})
}
func TestXrayHY2UDPAccountingAndRevocationWithRealCore(t *testing.T) {
	testCoreAccounting(t, "xray", true, []string{"hysteria2"})
}

func testCoreAccounting(t *testing.T, kind string, udp bool, templates []string) {
	clientBinary := os.Getenv("MXIOC_TEST_SING_BOX")
	binary := clientBinary
	if kind == "xray" {
		binary = os.Getenv("MXIOC_TEST_XRAY")
	}
	if binary == "" || clientBinary == "" {
		t.Skip("set MXIOC_TEST_SING_BOX to a build with with_v2ray_api and with_quic")
	}
	freePort := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	for _, template := range templates {
		t.Run(template, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cert, key := templateTestCertificate(t, "node.example.com", false)
			row, err := buildInboundTemplate(Record{"template": template, "port": freePort(), "serverName": "node.example.com", "certFile": "/fixture/cert", "keyFile": "/fixture/key", "grpcService": "accounting", "path": "/accounting"}, "1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}
			if template == "vless-reality" {
				pair, err := tls.LoadX509KeyPair(cert, key)
				if err != nil {
					t.Fatal(err)
				}
				fallback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(404) }))
				fallback.Config.ErrorLog = log.New(io.Discard, "", 0)
				fallback.EnableHTTP2 = true
				fallback.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, CurvePreferences: []tls.CurveID{tls.X25519}}
				fallback.StartTLS()
				defer fallback.Close()
				row["streamSettings"].(Record)["realitySettings"].(Record)["target"] = fallback.Listener.Addr().String()
			}
			if tlsTemplate(template) {
				row["streamSettings"].(Record)["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "keyFile": key}}
			}
			if template == "tuic" && kind == "sing-box" {
				// TUIC has no implicit ALPN. Both fixture peers must opt in
				// before testing an explicit legacy scalar client ALPN.
				row["streamSettings"].(Record)["tlsSettings"].(Record)["alpn"] = []any{"h3"}
			}
			if template == "hysteria2" && kind == "sing-box" {
				row["protocol"] = "hysteria2"
				delete(row["settings"].(Record), "version")
				row["streamSettings"].(Record)["network"] = "tcp"
				delete(row["streamSettings"].(Record), "hysteriaSettings")
			}
			row["id"], row["tag"], row["listen"], row["goCreateKey"] = 17, "mxioc-inbound-17", "127.0.0.1", "accounting-fixture"
			users := []Record{}
			for i := 0; i < 2; i++ {
				user, err := NewUser(row)
				if err != nil {
					t.Fatal(err)
				}
				users = append(users, user)
			}
			row["settings"].(Record)["clients"] = []any{users[0], users[1]}
			nodes, err := InboundNodes(row, Record{"host": "node.example.com"})
			if err != nil || len(nodes) != 2 {
				t.Fatal("user export missing", err)
			}
			apiAddress := "127.0.0.1:" + value(freePort())
			stats := Record{"listen": apiAddress, "binary": "go-ssh-grpc", "users": []any{users[0]["email"], users[1]["email"]}}
			if kind == "xray" {
				stats["binary"] = "/usr/local/bin/xray"
			}
			var serverDoc Record
			startServer := func() (func(), *capture) {
				native, err := legacyNativeInbound(kind, row)
				if err != nil {
					t.Fatal(err)
				}
				outbound := Record{"type": "direct", "tag": "direct"}
				if kind == "xray" {
					outbound = Record{"protocol": "freedom", "settings": Record{"finalRules": []any{Record{"action": "allow", "network": "tcp,udp", "ip": []any{"127.0.0.1/32"}}}}}
				}
				// Older Xray uses ipsBlocked instead of finalRules. This
				// opt-in is confined to the loopback interoperability fixture.
				if kind == "xray" && os.Getenv("MXIOC_TEST_XRAY_LEGACY_FREEDOM") == "1" {
					outbound["settings"] = Record{"ipsBlocked": []any{}}
				}
				serverDoc, err = planCoreStats(kind, Record{"inbounds": []any{native}, "outbounds": []any{outbound}})
				if err != nil {
					t.Fatal(err)
				}
				api, _ := serverDoc["api"].(Record)
				if kind == "sing-box" {
					api = serverDoc["experimental"].(Record)["v2ray_api"].(Record)
					api["stats"].(Record)["users"] = stats["users"]
				}
				api["listen"] = apiAddress
				_, port, _ := net.SplitHostPort(apiAddress)
				n, _ := parsedPort(port, 0)
				return startSSFixtureCore(t, ctx, binary, kind, serverDoc, n)
			}
			stop, serverLog := startServer()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "sing-accounting-proof") }))
			defer target.Close()
			var udpTarget *net.UDPConn
			if udp {
				udpTarget, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
				if err != nil {
					t.Fatal(err)
				}
				done := make(chan struct{})
				go func() {
					defer close(done)
					buf := make([]byte, 65535)
					for {
						n, peer, err := udpTarget.ReadFromUDP(buf)
						if err != nil {
							return
						}
						udpTarget.WriteToUDP(buf[:n], peer)
					}
				}()
				defer func() { udpTarget.Close(); <-done }()
			}
			var mutateClient func(Record)
			request := func(index int, allowed bool) {
				t.Helper()
				uri, err := links.Export(nodes[index])
				if err != nil {
					t.Fatal(err)
				}
				node, err := links.Parse(uri)
				if err != nil {
					t.Fatal(err)
				}
				if wsTemplate(template) && index == 1 {
					// Existing YAML nodes can still contain the old empty Host.
					node["ws-opts"].(Record)["headers"].(Record)["Host"] = ""
				}
				// The second QUIC user exercises a migrated Python YAML shape:
				// implicit TLS, legacy SNI alias, and HY2 rates with units.
				if kind == "sing-box" && index == 1 && (template == "hysteria2" || template == "tuic") {
					delete(node, "tls")
					node["alpn"] = "h3" // Legacy scalar ALPN must become a native array.
					node["servername"] = node["sni"]
					delete(node, "sni")
					if template == "tuic" {
						delete(node, "congestion-controller")
						delete(node, "udp-relay-mode")
					}
					if template == "hysteria2" {
						node["up"], node["down"] = "50 Mbps", "100 Mbps"
					}
				}
				if index == 1 && template == "vless-reality" {
					node["sni"] = node["servername"]
					delete(node, "servername")
				}
				if index == 1 && node["type"] == "trojan" {
					delete(node, "tls") // Legacy Python YAML uses implicit Trojan TLS.
				}
				if mutateClient != nil {
					mutateClient(node)
				}
				out, err := singRelayOutbound(node, "proxy")
				if err != nil {
					t.Fatal(err)
				}
				out["server"] = "127.0.0.1"
				if tls, ok := out["tls"].(Record); ok && template != "vless-reality" {
					tls["certificate_path"] = cert
				}
				port := freePort()
				clientKind, chosenBinary := "sing-box", clientBinary
				clientDoc := Record{"inbounds": []any{Record{"type": "socks", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{out}}
				if kind == "xray" && template == "vless-reality" && os.Getenv("MXIOC_TEST_REALITY_CROSS_CORE") != "1" {
					nativeOut, err := NodeOutbound(node, "proxy")
					if err != nil {
						t.Fatal(err)
					}
					nativeOut["settings"].(Record)["address"] = "127.0.0.1"
					clientKind, chosenBinary = "xray", binary
					clientDoc = Record{"inbounds": []any{Record{"protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": Record{"auth": "noauth", "udp": true}}}, "outbounds": []any{nativeOut}}
				}
				stopClient, clientLog := startSSFixtureCore(t, ctx, chosenBinary, clientKind, clientDoc, port)
				var requestErr error
				var body []byte
				if udp {
					requestErr = socksUDPProbe("127.0.0.1:"+value(port), udpTarget.LocalAddr().String(), []byte("sing-accounting-proof"))
					if requestErr == nil {
						body = []byte("sing-accounting-proof")
					}
				} else {
					proxy, _ := url.Parse("socks5://127.0.0.1:" + value(port))
					transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
					response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL)
					if response != nil {
						body, _ = io.ReadAll(response.Body)
						response.Body.Close()
					}
					transport.CloseIdleConnections()
					requestErr = err
				}
				stopClient()
				if (requestErr == nil && string(body) == "sing-accounting-proof") != allowed {
					a, _ := serverLog.result()
					b, _ := clientLog.result()
					t.Fatal("protocol authentication failed", allowed, requestErr, a, b)
				}
			}
			queryCtx := context.WithValue(ctx, coreStatsQueryKey{}, coreStatsQuery(func(ctx context.Context, address string) (string, error) {
				return querySingStats(ctx, address, (&net.Dialer{}).DialContext)
			}))
			counts := func() map[string]coreTraffic {
				t.Helper()
				counts, err := queryCoreCounters(queryCtx, kind, serverDoc, stats, func(ctx context.Context, _ string, _ int) (string, error) {
					output, err := exec.CommandContext(ctx, binary, "api", "statsquery", "--server="+apiAddress, "--pattern=user>>>").Output()
					return string(output), err
				})
				if err != nil {
					t.Fatal(err)
				}
				return counts
			}
			if template == "vless-reality" {
				key, err := ecdh.X25519().GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
				for _, mutate := range []func(Record){
					func(n Record) {
						n["reality-opts"].(Record)["public-key"] = base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
					},
					func(n Record) { n["reality-opts"].(Record)["short-id"] = "ffffffffffffffff" },
					func(n Record) { n["servername"] = "wrong-sni.invalid"; delete(n, "sni") },
				} {
					mutateClient = mutate
					request(0, false)
				}
				mutateClient = nil
			}
			firstName, secondName := value(users[0]["email"]), value(users[1]["email"])
			if initial := counts(); initial[firstName] != (coreTraffic{}) || initial[secondName] != (coreTraffic{}) {
				t.Fatal("idle baseline not zero")
			}
			request(0, true)
			first := counts()[firstName]
			if first.up <= 0 || first.down <= 0 || counts()[secondName] != (coreTraffic{}) {
				t.Fatal("first user not independently counted")
			}
			request(1, true)
			both := counts()
			if both[firstName] != first || both[secondName].up <= 0 || both[secondName].down <= 0 {
				t.Fatal("second user not independently counted")
			}
			if idle := counts(); idle[firstName] != both[firstName] || idle[secondName] != both[secondName] {
				t.Fatal("idle query changed counters")
			}
			apply := func(operation string, user Record) {
				t.Helper()
				binding := bindingFor(t, row, user)
				binding["inboundId"] = 17
				if operation == "resume" {
					binding["monthlyPaused"] = true
				}
				next, rows, err := planCoreUserChange(kind, operation, legacyCoreState{Inbounds: []Record{row}, UserStats: stats}, serverDoc, binding, false)
				if err != nil {
					t.Fatal(err)
				}
				row, serverDoc = rows[0], next
			}
			stop()
			apply("remove", users[0])
			stop, serverLog = startServer()
			request(0, false)
			request(1, true)
			stop()
			apply("pause", users[1])
			stop, serverLog = startServer()
			request(1, false)
			stop()
			apply("resume", anyRecords(row["settings"].(Record)["clients"])[0])
			stop, serverLog = startServer()
			request(1, true)
			stop()
			apply("remove", anyRecords(row["settings"].(Record)["clients"])[0])
			stop, serverLog = startServer()
			request(1, false)
			stop()
		})
	}
}
