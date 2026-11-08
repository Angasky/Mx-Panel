package remote

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestSingSOCKSUDPRestrictionWithRealCore(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_SING_BOX")
	if binary == "" {
		t.Skip("set MXIOC_TEST_SING_BOX")
	}
	port := func() int {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		return l.Addr().(*net.TCPAddr).Port
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	serverPort := port()
	stop, _ := startSSFixtureCore(t, ctx, binary, "sing-box", Record{
		"inbounds":  []any{Record{"type": "socks", "listen": "127.0.0.1", "listen_port": serverPort, "users": []any{Record{"username": "user", "password": "fixture-secret"}}}},
		"outbounds": []any{Record{"type": "direct"}},
	}, serverPort)
	defer stop()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "tcp-only-proof") }))
	defer target.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	var received atomic.Int32
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			n, peer, err := udp.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			received.Add(1)
			udp.WriteToUDP(buffer[:n], peer)
		}
	}()
	defer func() { udp.Close(); <-done }()
	// Enabled cases before and after the restriction prove that failed UDP
	// is caused by the policy, not by an unavailable echo endpoint or proxy.
	for _, enabled := range []bool{true, false, true} {
		suffix := "true"
		if !enabled {
			suffix = "false"
		}
		t.Run("udp="+suffix, func(t *testing.T) {
			node, err := links.Parse("socks5://user:fixture-secret@node.example.net:" + value(serverPort) + "?udp=" + suffix)
			if err != nil {
				t.Fatal(err)
			}
			out, err := singRelayOutbound(node, "proxy")
			if err != nil {
				t.Fatal(err)
			}
			out["server"] = "127.0.0.1"
			clientPort := port()
			stop, coreLog := startSSFixtureCore(t, ctx, binary, "sing-box", Record{"inbounds": []any{Record{"type": "socks", "listen": "127.0.0.1", "listen_port": clientPort}}, "outbounds": []any{out}}, clientPort)
			defer stop()
			address := "127.0.0.1:" + value(clientPort)
			proxyURL, _ := url.Parse("socks5://" + address)
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
			defer transport.CloseIdleConnections()
			response, err := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL)
			if err != nil {
				output, _ := coreLog.result()
				t.Fatal("TCP blocked", err, output)
			}
			body, _ := io.ReadAll(response.Body)
			response.Body.Close()
			if string(body) != "tcp-only-proof" {
				t.Fatal("TCP response changed")
			}
			before := received.Load()
			err = socksUDPProbe(address, udp.LocalAddr().String(), []byte("udp-policy-proof"))
			if enabled && (err != nil || received.Load() <= before) {
				output, _ := coreLog.result()
				t.Fatal("UDP baseline failed", err, output)
			}
			if !enabled && (err == nil || received.Load() != before) {
				t.Fatal("disabled UDP reached target")
			}
		})
	}
}
