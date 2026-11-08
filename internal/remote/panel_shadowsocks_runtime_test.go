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

func TestPanelShadowsocksTCPAndUDPWithRealCore(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary == "" {
		t.Skip("set MXIOC_TEST_XRAY")
	}
	for _, kind := range []string{"xray", "sing-box"} {
		t.Run(kind, func(t *testing.T) {
			serverBinary := binary
			if kind == "sing-box" {
				serverBinary = os.Getenv("MXIOC_TEST_SING_BOX")
				if serverBinary == "" {
					t.Skip("set MXIOC_TEST_SING_BOX")
				}
			}
			port := func() int {
				l, e := net.Listen("tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				defer l.Close()
				return l.Addr().(*net.TCPAddr).Port
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			row, err := buildPanelShadowsocks(Record{"template": "shadowsocks", "port": port()})
			if err != nil {
				t.Fatal(err)
			}
			row["listen"] = "127.0.0.1"
			native, err := legacyNativeInbound(kind, row)
			if err != nil {
				t.Fatal(err)
			}
			out := Record{"protocol": "freedom", "settings": Record{"finalRules": []any{Record{"action": "allow", "network": "tcp,udp", "ip": []any{"127.0.0.1/32"}}}}}
			if kind == "sing-box" {
				out = Record{"type": "direct"}
			}
			stop, _ := startSSFixtureCore(t, ctx, serverBinary, kind, Record{"inbounds": []any{native}, "outbounds": []any{out}}, row["port"].(int))
			defer stop()
			nodes, err := InboundNodes(row, Record{"host": "node.example.net"})
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
			proxy, err := NodeOutbound(node, "proxy")
			if err != nil {
				t.Fatal(err)
			}
			proxy["settings"].(Record)["servers"].([]any)[0].(Record)["address"] = "127.0.0.1"
			clientPort := port()
			stopClient, _ := startSSFixtureCore(t, ctx, binary, "xray", Record{"inbounds": []any{Record{"protocol": "socks", "listen": "127.0.0.1", "port": clientPort, "settings": Record{"auth": "noauth", "udp": true}}}, "outbounds": []any{proxy}}, clientPort)
			defer stopClient()
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ss-panel-proof") }))
			defer target.Close()
			address := "127.0.0.1:" + value(clientPort)
			proxyURL, _ := url.Parse("socks5://" + address)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Get(target.URL)
			if err != nil {
				t.Fatal(err)
			}
			body, err := io.ReadAll(response.Body)
			response.Body.Close()
			if err != nil || string(body) != "ss-panel-proof" {
				t.Fatal("TCP forwarding failed", err)
			}
			udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			go func() {
				defer close(done)
				buffer := make([]byte, 4096)
				for {
					n, peer, err := udp.ReadFromUDP(buffer)
					if err != nil {
						return
					}
					udp.WriteToUDP(buffer[:n], peer)
				}
			}()
			defer func() { udp.Close(); <-done }()
			if err := socksUDPProbe(address, udp.LocalAddr().String(), []byte("ss-panel-udp-proof")); err != nil {
				t.Fatal(err)
			}

		})
	}
}
