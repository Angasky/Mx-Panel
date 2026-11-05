package remote

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
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
)

func TestSingBoxRealityProbeWithRealCores(t *testing.T) {
	xray, sing := os.Getenv("MXIOC_TEST_XRAY"), os.Getenv("MXIOC_TEST_SING_BOX")
	if xray == "" || sing == "" {
		t.Skip("set MXIOC_TEST_XRAY and MXIOC_TEST_SING_BOX for native SNI probe verification")
	}
	script, err := realityProbeScriptForCore("sing-box", []sniTarget{{"node.example.com", "1.1.1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	server, client := probeConfigs(t, script)
	cert, key := templateTestCertificate(t, "node.example.com", false)
	pair, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		t.Fatal(err)
	}
	fallback := httptest.NewUnstartedServer(http.NotFoundHandler())
	fallback.Config.ErrorLog = log.New(io.Discard, "", 0)
	fallback.EnableHTTP2 = true
	fallback.TLS = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, CurvePreferences: []tls.CurveID{tls.X25519}}
	fallback.StartTLS()
	defer fallback.Close()
	inbound := anyRecords(server["inbounds"])[0]
	handshake := inbound["tls"].(Record)["reality"].(Record)["handshake"].(Record)
	handshake["server"] = "127.0.0.1"
	handshake["server_port"] = fallback.Listener.Addr().(*net.TCPAddr).Port
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	start := func(binary, flag string, config Record, port string) (func(), *capture) {
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		file := filepath.Join(t.TempDir(), "config.json")
		if err := os.WriteFile(file, raw, 0600); err != nil {
			t.Fatal(err)
		}
		command := exec.CommandContext(ctx, binary, "run", flag, file)
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
			conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 50*time.Millisecond)
			if err == nil {
				conn.Close()
				return stop, output
			}
			time.Sleep(20 * time.Millisecond)
		}
		data, _ := output.result()
		t.Fatal("probe process did not listen", data)
		return nil, nil
	}
	_, serverLog := start(sing, "-c", server, fmt.Sprint(inbound["listen_port"]))
	// Index zero is the blackhole sink. Only index one traverses Reality.
	port := fmt.Sprint(anyRecords(client["inbounds"])[1]["port"])
	for _, allowed := range []bool{true, false} {
		if !allowed {
			anyRecords(client["outbounds"])[1]["streamSettings"].(Record)["realitySettings"].(Record)["shortId"] = "ffffffffffffffff"
		}
		stop, clientLog := start(xray, "-config", client, port)
		proxy, _ := url.Parse("socks5://127.0.0.1:" + port)
		transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
		response, requestErr := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Head("http://reality-probe.invalid/")
		passed := requestErr == nil && response.StatusCode == 403
		if response != nil {
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		stop()
		if passed != allowed {
			a, _ := serverLog.result()
			b, _ := clientLog.result()
			t.Fatal("sing-box probe bypassed Reality or failed its data path", allowed, requestErr, a, b)
		}
	}
}
