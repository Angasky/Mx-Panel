package config

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/links"
	"go.yaml.in/yaml/v3"
)

// MXIOC_TEST_SNELL_REUSE=1 reproduces intermittent Mihomo 1.19.33
// v4/v5 reused-stream EOF/502 after a successful readiness request.
// Default exercises all five protocol versions without optional reuse.
func TestGoSnellHTTPWithRealMihomo(t *testing.T)                 { testGoSnellHTTP(t, false) }
func TestGoSnellRejectsWrongPasswordWithRealMihomo(t *testing.T) { testGoSnellHTTP(t, true) }
func testGoSnellHTTP(t *testing.T, wrongPassword bool) {
	binary := os.Getenv("MXIOC_MIHOMO_BIN")
	if binary == "" {
		t.Skip("set MXIOC_MIHOMO_BIN")
	}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "go-snell-proof") }))
	defer target.Close()
	for version := 1; version <= 5; version++ {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			// Reserve both ports at once, so the OS cannot hand out the same port twice.
			a, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			b, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			snellPort, mixed := a.Addr().(*net.TCPAddr).Port, b.Addr().(*net.TCPAddr).Port
			node := Document{"name": "Snell", "type": "snell", "server": "127.0.0.1", "port": snellPort, "psk": "isolated-fixture-password", "version": version, "udp": version >= 3, "reuse": version >= 4 && os.Getenv("MXIOC_TEST_SNELL_REUSE") == "1"}
			if err := ValidateNode(node); err != nil {
				t.Fatal(err)
			}
			uri, err := links.Export(node)
			if err != nil {
				t.Fatal(err)
			}
			node, err = links.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			if wrongPassword {
				node["psk"] = "incorrect-fixture-password"
			}
			raw, err := yaml.Marshal(Document{"mixed-port": mixed, "bind-address": "127.0.0.1", "allow-lan": false, "log-level": "debug", "mode": "rule", "listeners": []any{Document{"name": "local-snell", "type": "snell", "listen": "127.0.0.1", "port": snellPort, "psk": "isolated-fixture-password", "version": version, "udp": version >= 3, "proxy": "DIRECT"}}, "proxies": []any{node}, "rules": []any{"MATCH,Snell"}})
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			file := filepath.Join(dir, "config.yaml")
			if err = os.WriteFile(file, raw, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var logs bytes.Buffer
			cmd := exec.CommandContext(ctx, binary, "-d", dir, "-f", file)
			cmd.Stdout = &logs
			cmd.Stderr = &logs
			a.Close()
			b.Close()
			if err = cmd.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() {
				cancel()
				_ = cmd.Wait()
				if t.Failed() {
					t.Log(logs.String())
				}
			}()
			for _, port := range []int{snellPort, mixed} {
				deadline := time.Now().Add(5 * time.Second)
				for {
					c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 100*time.Millisecond)
					if err == nil {
						c.Close()
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("listener did not start", err)
					}
					time.Sleep(20 * time.Millisecond)
				}
			}
			proxyURL, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(mixed))
			transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DisableKeepAlives: true}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			if wrongPassword {
				response, err := client.Get(target.URL)
				if response != nil {
					body, _ := io.ReadAll(response.Body)
					response.Body.Close()
					if err == nil && response.StatusCode == 200 && string(body) == "go-snell-proof" {
						t.Fatal("wrong password accepted")
					}
				}
				return
			}
			// Listening is not readiness: Mihomo opens sockets before publishing
			// its initial rules. Require one completed probe, then all three
			// assertions below run without retries (including reused streams).
			deadline := time.Now().Add(5 * time.Second)
			for {
				response, probeErr := client.Get(target.URL)
				ready := false
				if probeErr == nil {
					body, readErr := io.ReadAll(response.Body)
					response.Body.Close()
					ready = readErr == nil && response.StatusCode == 200 && string(body) == "go-snell-proof"
				}
				if ready {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("Mihomo data plane not ready", probeErr)
				}
				time.Sleep(20 * time.Millisecond)
			}
			if version >= 3 {
				snellUDPProof(t, mixed)
			}
			for attempt := 0; attempt < 3; attempt++ {
				response, err := client.Get(target.URL)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(body) != "go-snell-proof" {
					t.Fatalf("status=%d body=%q err=%v", response.StatusCode, body, err)
				}
			}
		})
	}
}

// Exercise packet boundaries through the actual SOCKS -> Snell -> UDP path.
func snellUDPProof(t *testing.T, port int) {
	t.Helper()
	target, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	target.SetDeadline(time.Now().Add(5 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		b := make([]byte, 4096)
		for {
			n, addr, err := target.ReadFrom(b)
			if err != nil {
				return
			}
			target.WriteTo(b[:n], addr)
		}
	}()
	defer func() { target.Close(); <-done }()
	control, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err = control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	greeting := make([]byte, 2)
	if _, err = io.ReadFull(control, greeting); err != nil || !bytes.Equal(greeting, []byte{5, 0}) {
		t.Fatal("SOCKS greeting", greeting, err)
	}
	if _, err = control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	header := make([]byte, 4)
	if _, err = io.ReadFull(control, header); err != nil || header[1] != 0 {
		t.Fatal("UDP associate", header, err)
	}
	size := 4
	if header[3] == 4 {
		size = 16
	} else if header[3] != 1 {
		t.Fatal("unexpected UDP bind address", header)
	}
	address := make([]byte, size+2)
	if _, err = io.ReadFull(control, address); err != nil {
		t.Fatal(err)
	}
	endpoint := &net.UDPAddr{IP: net.IP(address[:size]), Port: int(binary.BigEndian.Uint16(address[size:]))}
	if endpoint.IP.IsUnspecified() {
		endpoint.IP = net.ParseIP("127.0.0.1")
	}
	socket, err := net.DialUDP("udp", nil, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	socket.SetDeadline(time.Now().Add(5 * time.Second))
	dest := target.LocalAddr().(*net.UDPAddr)
	for _, size := range []int{1, 1200, 3000} {
		proof := bytes.Repeat([]byte{byte(size % 251)}, size)
		packet := append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(dest.Port >> 8), byte(dest.Port)}, proof...)
		if _, err = socket.Write(packet); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 4096)
		n, err := socket.Read(response)
		if err != nil || n != len(packet) || !bytes.Equal(response[:n], packet) {
			t.Fatalf("UDP size %d: n=%d err=%v", size, n, err)
		}
	}
}
