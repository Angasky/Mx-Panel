package subscriptions

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/managednodes"
	"go.yaml.in/yaml/v3"
)

// Real Xray observes two isolated SOCKS paths. Their HTTP responses identify
// the path; an actual local origin detects any accidental DIRECT fallback.
func TestXrayHAFailoverRecoveryAndRejectWithRealCore(t *testing.T) {
	testNativeHAFailover(t, "xray", os.Getenv("MXIOC_TEST_XRAY"))
}

func TestMihomoHAFailoverRecoveryAndRejectWithRealCore(t *testing.T) {
	testNativeHAFailover(t, "mihomo", os.Getenv("MXIOC_TEST_MIHOMO"))
}

func testNativeHAFailover(t *testing.T, kind, binary string) {
	if binary == "" {
		t.Skip("set the corresponding MXIOC_TEST_XRAY or MXIOC_TEST_MIHOMO binary for native failover verification")
	}
	var direct atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		direct.Add(1)
		io.WriteString(w, "unexpected-direct")
	}))
	defer origin.Close()
	pathListener := func(address, name string) net.Listener {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { listener.Close() })
		go func() {
			for {
				connection, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer connection.Close()
					connection.SetDeadline(time.Now().Add(3 * time.Second))
					reader := bufio.NewReader(connection)
					var header [2]byte
					if _, err := io.ReadFull(reader, header[:]); err != nil || header[0] != 5 {
						return
					}
					if _, err := io.CopyN(io.Discard, reader, int64(header[1])); err != nil {
						return
					}
					connection.Write([]byte{5, 0})
					var request [4]byte
					if _, err := io.ReadFull(reader, request[:]); err != nil || request[0] != 5 || request[1] != 1 {
						return
					}
					size := 0
					switch request[3] {
					case 1:
						size = 4
					case 4:
						size = 16
					case 3:
						length, err := reader.ReadByte()
						if err != nil {
							return
						}
						size = int(length)
					default:
						return
					}
					if _, err := io.CopyN(io.Discard, reader, int64(size+2)); err != nil {
						return
					}
					connection.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
					httpRequest, err := http.ReadRequest(reader)
					if err != nil {
						return
					}
					httpRequest.Body.Close()
					if httpRequest.URL.Path == "/health" {
						if name == "primary" {
							time.Sleep(40 * time.Millisecond) // Backup is faster; priority must still win.
						}
						io.WriteString(connection, "HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
					} else {
						fmt.Fprintf(connection, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(name), name)
					}
				}()
			}
		}()
		return listener
	}
	primary := pathListener("127.0.0.1:0", "primary")
	backup := pathListener("127.0.0.1:0", "backup")
	primaryAddress, backupAddress := primary.Addr().String(), backup.Addr().String()
	freePort := func() int {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port
	}
	nodes := []Record{
		{"name": "primary", "type": "socks5", "server": "primary.example.net", "port": primary.Addr().(*net.TCPAddr).Port},
		{"name": "backup", "type": "socks5", "server": "backup.example.net", "port": backup.Addr().(*net.TCPAddr).Port},
	}
	clientConfig, err := xrayFailover(Record{"name": "native-priority-proof"}, nodes, 1)
	if err != nil {
		t.Fatal(err)
	}
	clientPort := freePort()
	if kind == "mihomo" {
		clientConfig = activatedMihomoHA(t, nodes)
		clientConfig["mixed-port"], clientConfig["allow-lan"], clientConfig["bind-address"] = clientPort, false, "127.0.0.1"
		clientConfig["rules"] = []any{"MATCH,native-priority-proof"}
		for _, node := range objects(clientConfig["proxies"]) {
			node["server"] = "127.0.0.1"
		}
		for _, group := range objects(clientConfig["proxy-groups"]) {
			if group["name"] == "native-priority-proof" {
				group["url"], group["interval"] = origin.URL+"/health", 1
			}
		}
	} else {
		inbounds := clientConfig["inbounds"].([]any)
		inbounds[0].(Record)["port"] = clientPort
		clientConfig["inbounds"] = inbounds[:1]
		for _, value := range clientConfig["outbounds"].([]any)[:2] {
			value.(Record)["settings"].(Record)["servers"].([]any)[0].(Record)["address"] = "127.0.0.1"
		}
		clientConfig["observatory"].(Record)["probeURL"] = origin.URL + "/health"
	}
	// Fixtures only substitute loopback endpoints and speed up health checks;
	// the production priority/fallback structure comes from the Go generators.
	raw, err := json.Marshal(clientConfig)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	file, logFile := filepath.Join(root, "client.json"), filepath.Join(root, "client.log")
	if err := os.WriteFile(file, raw, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(logFile)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	args := []string{"run", "-config", file}
	if kind == "mihomo" {
		args = []string{"-d", root, "-f", file}
	}
	command := exec.CommandContext(ctx, binary, args...)
	command.Stdout, command.Stderr = log, log
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		command.Process.Kill()
		command.Wait()
		if t.Failed() {
			output, _ := os.ReadFile(logFile)
			t.Log(string(output))
		}
	}()
	proxy, _ := url.Parse("socks5://127.0.0.1:" + strconv.Itoa(clientPort))
	transport := &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 1200 * time.Millisecond}
	fetch := func() string {
		response, err := client.Get(origin.URL + "/proof")
		if err != nil {
			return "rejected"
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(response.Body, 1024))
		return strings.TrimSpace(string(body))
	}
	waitFor := func(expected string) {
		until := time.Now().Add(9 * time.Second)
		last := ""
		for time.Now().Before(until) {
			last = fetch()
			if last == expected {
				return
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("failover did not reach %s; last result %s", expected, last)
	}
	waitFor("primary")
	for i := 0; i < 4; i++ {
		if got := fetch(); got != "primary" {
			t.Fatal("healthy priority became latency balancing", got)
		}
	}
	primary.Close()
	waitFor("backup")
	primary = pathListener(primaryAddress, "primary")
	waitFor("primary")
	primary.Close()
	backup.Close()
	time.Sleep(2300 * time.Millisecond)
	for i := 0; i < 3; i++ {
		if got := fetch(); got != "rejected" {
			t.Fatal("all-dead paths did not reject", got)
		}
	}
	backup = pathListener(backupAddress, "backup")
	waitFor("backup")
	if direct.Load() != 0 {
		t.Fatal("health probes or user requests bypassed the managed paths", direct.Load())
	}
	t.Log("primary preferred; backup takeover; primary recovery; all-dead reject; backup recovery; no direct traffic")
}

func activatedMihomoHA(t *testing.T, nodes []Record) Record {
	t.Helper()
	c, _, _ := controllerFixture(t)
	if err := c.Repository.Mutate("clash", func(doc Record) error {
		doc["proxies"] = []any{nodes[0], nodes[1]}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	operation := strings.Repeat("a", 32)
	paths, entries, requests, bindings, chains := []any{}, []any{}, []any{}, []any{}, []any{}
	for i, node := range nodes {
		request := config.FailoverPathRequest(operation, i)
		name := node["name"]
		paths, entries, requests = append(paths, name), append(entries, name), append(requests, request)
		chains = append(chains, Record{"name": name, "entry": name, "exit": "fixed", "serverId": name, "inboundId": 1, "requestId": request})
		bindings = append(bindings, Record{"serverId": name, "inboundId": 1, "status": "active", "chainRequest": request,
			"importedNodes": []any{Record{"name": name, "identity": managednodes.Identity(node)}}})
	}
	if err := c.Repository.UpdateState("clash", func(state Record) error {
		state["serverChains"], state["remoteNodes"] = chains, bindings
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	plan := Record{"name": "native-priority-proof", "paths": paths, "entries": entries, "exit": "fixed", "pathRequests": requests,
		"requestId": operation, "requestHash": "fixture", "status": "creating", "interval": 10, "groups": []any{}}
	if err := c.Repository.BeginFailover("clash", plan); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Repository.ActivateFailover("clash", plan); err != nil {
		t.Fatal(err)
	}
	source, err := c.Repository.ConversionSource("clash", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var doc Record
	if err := yaml.Unmarshal(source.Raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}
