package remote

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

// Exercise the production template -> URI -> client mapping -> authenticated
// traffic -> counter query and revocation chain, without remote infrastructure.
func TestSingBoxProtocolsAccountingAndRevocationWithRealCore(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_SING_BOX")
	if binary == "" {
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
	for _, template := range []string{"vmess-tcp", "vless-tcp-tls", "vmess-tcp-tls", "trojan-tls", "vless-ws-tls", "vmess-ws-tls", "trojan-ws-tls", "vless-grpc-tls", "vmess-grpc-tls", "trojan-grpc-tls", "hysteria2", "tuic"} {
		t.Run(template, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			cert, key := templateTestCertificate(t, "node.example.com", false)
			row, err := buildInboundTemplate(Record{"template": template, "port": freePort(), "serverName": "node.example.com", "certFile": "/fixture/cert", "keyFile": "/fixture/key", "grpcService": "accounting", "path": "/accounting"}, "")
			if err != nil {
				t.Fatal(err)
			}
			if tlsTemplate(template) {
				row["streamSettings"].(Record)["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "keyFile": key}}
			}
			if template == "hysteria2" {
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
			var serverDoc Record
			startServer := func() (func(), *capture) {
				native, err := legacyNativeInbound("sing-box", row)
				if err != nil {
					t.Fatal(err)
				}
				serverDoc, err = planCoreStats("sing-box", Record{"inbounds": []any{native}, "outbounds": []any{Record{"type": "direct", "tag": "direct"}}})
				if err != nil {
					t.Fatal(err)
				}
				api := serverDoc["experimental"].(Record)["v2ray_api"].(Record)
				api["listen"] = apiAddress
				api["stats"].(Record)["users"] = stats["users"]
				_, port, _ := net.SplitHostPort(apiAddress)
				n, _ := parsedPort(port, 0)
				return startSSFixtureCore(t, ctx, binary, "sing-box", serverDoc, n)
			}
			stop, serverLog := startServer()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "sing-accounting-proof") }))
			defer target.Close()
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
				out, err := singRelayOutbound(node, "proxy")
				if err != nil {
					t.Fatal(err)
				}
				out["server"] = "127.0.0.1"
				if tls, ok := out["tls"].(Record); ok {
					tls["certificate_path"] = cert
				}
				port := freePort()
				stopClient, clientLog := startSSFixtureCore(t, ctx, binary, "sing-box", Record{"inbounds": []any{Record{"type": "socks", "listen": "127.0.0.1", "listen_port": port}}, "outbounds": []any{out}}, port)
				proxy, _ := url.Parse("socks5://127.0.0.1:" + value(port))
				transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
				response, requestErr := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL)
				var body []byte
				if response != nil {
					body, _ = io.ReadAll(response.Body)
					response.Body.Close()
				}
				transport.CloseIdleConnections()
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
				counts, err := queryCoreCounters(queryCtx, "sing-box", serverDoc, stats, nil)
				if err != nil {
					t.Fatal(err)
				}
				return counts
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
				next, rows, err := planCoreUserChange("sing-box", operation, legacyCoreState{Inbounds: []Record{row}, UserStats: stats}, serverDoc, binding, false)
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
