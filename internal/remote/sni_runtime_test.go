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
	"strings"
	"testing"
	"time"
)

// Optional real-core test. It only contacts a local TLS server and modifies
// copies of generated test configs; no public SNI, production port or SSH is used.
func TestNativeRealityProbeWithLocalTLSAndRealXray(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary == "" {
		t.Skip("set MXIOC_TEST_XRAY for isolated real-core verification")
	}
	target := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(418) }))
	target.EnableHTTP2 = true
	target.Config.ErrorLog = log.New(io.Discard, "", 0)
	target.TLS = &tls.Config{MinVersion: tls.VersionTLS13}
	target.StartTLS()
	t.Cleanup(target.Close)
	script, err := realityProbeScript([]sniTarget{{"example.com", "8.8.8.8"}})
	if err != nil {
		t.Fatal(err)
	}
	server, client := probeConfigs(t, script)
	serverIn := server["inbounds"].([]any)[0].(map[string]any)
	serverIn["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["target"] = strings.TrimPrefix(target.URL, "https://")
	reserve := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		return port
	}
	port, socks := reserve(), reserve()
	serverIn["port"] = port
	clientIn := client["inbounds"].([]any)[0].(map[string]any)
	clientIn["port"] = socks
	clientOut := client["outbounds"].([]any)[0].(map[string]any)
	clientOut["settings"].(map[string]any)["vnext"].([]any)[0].(map[string]any)["port"] = port
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	start := func(config Record, listen int) *exec.Cmd {
		raw, _ := json.Marshal(config)
		check := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
		check.Stdin = strings.NewReader(string(raw))
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatal("generated Xray config rejected", err, string(output))
		}
		command := exec.CommandContext(ctx, binary, "run", "-config", "stdin:")
		command.Stdin = strings.NewReader(string(raw))
		output := &capture{limit: 64 << 10}
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { command.Process.Kill(); command.Wait() })
		deadline := time.Now().Add(4 * time.Second)
		for time.Now().Before(deadline) {
			c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", value(listen)), 100*time.Millisecond)
			if err == nil {
				c.Close()
				return command
			}
			time.Sleep(30 * time.Millisecond)
		}
		log, _ := output.result()
		t.Fatal("isolated Xray did not listen", log)
		return nil
	}
	start(server, port)
	start(client, socks)
	checkProxy := func(port int) (int, error) {
		proxy, _ := url.Parse("socks5://" + net.JoinHostPort("127.0.0.1", value(port)))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
		defer transport.CloseIdleConnections()
		response, err := (&http.Client{Transport: transport, Timeout: 4 * time.Second}).Head("http://reality-probe.invalid/")
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		io.Copy(io.Discard, response.Body)
		return response.StatusCode, nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		status, err := checkProxy(socks)
		if err != nil || status != 403 {
			t.Fatal("Reality authenticated blackhole proof failed", attempt, status, err)
		}
	}
	// Wrong public key must not produce the 403 success proof even though TLS works.
	badSocks := reserve()
	clientIn["port"] = badSocks
	clientOut["streamSettings"].(map[string]any)["realitySettings"].(map[string]any)["publicKey"] = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	start(client, badSocks)
	if status, err := checkProxy(badSocks); err == nil && status == 403 {
		t.Fatal("wrong Reality key passed verification")
	}
	t.Log("real Xray: both Reality attempts passed; incorrect public key rejected; all targets loopback")
}
