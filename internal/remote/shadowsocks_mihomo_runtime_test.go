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

func TestManagedSSAEADWithRealMihomo(t *testing.T) {
	xray, mihomo := os.Getenv("MXIOC_TEST_XRAY"), os.Getenv("MXIOC_TEST_MIHOMO")
	if xray == "" || mihomo == "" {
		t.Skip("set MXIOC_TEST_XRAY and MXIOC_TEST_MIHOMO for native client interoperability")
	}
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	for _, template := range []string{"ss-aes-128-gcm", "ss-aes-256-gcm", "ss-chacha20-poly1305"} {
		t.Run(template, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			row := managedSSAEADFixture(t, template)
			row["port"], row["listen"] = port(), "127.0.0.1"
			user, err := NewUser(row)
			if err != nil {
				t.Fatal(err)
			}
			row["settings"].(Record)["clients"] = []any{user}
			nodes, err := InboundNodes(row, Record{"host": "127.0.0.1"})
			if err != nil || len(nodes) != 1 {
				t.Fatal(err)
			}
			uri, err := links.Export(nodes[0])
			if err != nil {
				t.Fatal(err)
			}
			node, err := links.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			native, err := legacyNativeInbound("xray", row)
			if err != nil {
				t.Fatal(err)
			}
			doc := Record{"inbounds": []any{native}, "outbounds": []any{Record{"protocol": "freedom", "settings": Record{"finalRules": []any{Record{"action": "allow", "network": "tcp", "ip": []any{"127.0.0.1/32"}}}}}}}
			stop, serverLog := startSSFixtureCore(t, ctx, xray, "xray", doc, row["port"].(int))
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "mihomo-ss-proof") }))
			defer target.Close()
			request := func(allowed bool) {
				t.Helper()
				socks := port()
				config := Record{"socks-port": socks, "allow-lan": false, "bind-address": "127.0.0.1", "mode": "rule", "log-level": "silent", "proxies": []any{node}, "proxy-groups": []any{Record{"name": "Proxy", "type": "select", "proxies": []any{node["name"]}}}, "rules": []any{"MATCH,Proxy"}}
				stopClient, clientLog := startSSFixtureCore(t, ctx, mihomo, "mihomo", config, socks)
				proxy, _ := url.Parse("socks5://127.0.0.1:" + value(socks))
				transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
				response, requestErr := (&http.Client{Transport: transport, Timeout: 1500 * time.Millisecond}).Get(target.URL)
				var body []byte
				if response != nil {
					body, _ = io.ReadAll(response.Body)
					response.Body.Close()
				}
				transport.CloseIdleConnections()
				stopClient()
				if (requestErr == nil && string(body) == "mihomo-ss-proof") != allowed {
					a, _ := serverLog.result()
					b, _ := clientLog.result()
					t.Fatal("Mihomo SS interoperability failed", allowed, requestErr, a, b)
				}
			}
			request(true)
			stop()
			binding := bindingFor(t, row, user)
			binding["inboundId"] = row["id"]
			next, _, err := planCoreUserChange("xray", "remove", legacyCoreState{Inbounds: []Record{row}}, doc, binding, false)
			if err != nil {
				t.Fatal(err)
			}
			stop, serverLog = startSSFixtureCore(t, ctx, xray, "xray", next, row["port"].(int))
			request(false)
			stop()
		})
	}
}
