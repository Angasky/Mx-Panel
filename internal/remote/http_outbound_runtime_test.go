package remote

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"log"
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

func TestHTTPConnectOutboundWithRealCores(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		binary := os.Getenv("MXIOC_TEST_XRAY")
		if kind == "sing-box" {
			binary = os.Getenv("MXIOC_TEST_SING_BOX")
		}
		t.Run(kind, func(t *testing.T) {
			if binary == "" {
				t.Skip("set MXIOC_TEST_XRAY / MXIOC_TEST_SING_BOX")
			}
			for _, secure := range []bool{false, true} {
				scheme := "http"
				if secure {
					scheme = "https"
				}
				t.Run(scheme, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "http-connect-proof") }))
					defer target.Close()
					targetURL, _ := url.Parse(target.URL)
					var accepted atomic.Int32
					var customHeaders atomic.Bool
					proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if customHeaders.Load() && (r.Header.Get("User-Agent") != "legacy-client/1" || r.Header.Get("X-Legacy-Route") != "literal-{{.Target}}") {
							http.Error(w, "missing custom headers", 400)
							return
						}
						if r.Method != "CONNECT" || r.Host != targetURL.Host {
							http.Error(w, "unexpected target", 400)
							return
						}
						if r.Header.Get("Proxy-Authorization") != "Basic "+base64.StdEncoding.EncodeToString([]byte("user:pass@word")) {
							w.Header().Set("Proxy-Authenticate", `Basic realm="fixture"`)
							w.WriteHeader(407)
							return
						}
						upstream, err := net.DialTimeout("tcp", targetURL.Host, time.Second)
						if err != nil {
							http.Error(w, "target unavailable", 502)
							return
						}
						defer upstream.Close()
						client, buffer, err := w.(http.Hijacker).Hijack()
						if err != nil {
							return
						}
						defer client.Close()
						client.SetDeadline(time.Now().Add(5 * time.Second))
						upstream.SetDeadline(time.Now().Add(5 * time.Second))
						buffer.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
						buffer.Flush()
						accepted.Add(1)
						done := make(chan struct{})
						go func() { io.Copy(upstream, buffer); upstream.(*net.TCPConn).CloseWrite(); close(done) }()
						io.Copy(client, upstream)
						client.Close()
						<-done
					}))
					proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
					cert, key := templateTestCertificate(t, "proxy.example.net", false)
					if secure {
						pair, err := tls.LoadX509KeyPair(cert, key)
						if err != nil {
							t.Fatal(err)
						}
						proxy.TLS = &tls.Config{Certificates: []tls.Certificate{pair}, MinVersion: tls.VersionTLS12}
						proxy.StartTLS()
					} else {
						proxy.Start()
					}
					defer proxy.Close()
					_, proxyPort, _ := net.SplitHostPort(proxy.Listener.Addr().String())
					cases := []string{"success", "wrong-password"}
					cases = append(cases, "custom-headers")
					if secure {
						cases = append(cases, "untrusted-certificate", "wrong-sni")
						if kind == "sing-box" {
							cases = append(cases, "explicit-insecure")
						}
					}
					for _, scenario := range cases {
						t.Run(scenario, func(t *testing.T) {
							customHeaders.Store(scenario == "custom-headers")
							uri := scheme + "://user:pass%40word@proxy.example.net:" + proxyPort
							if scenario == "wrong-password" {
								uri = scheme + "://user:wrong@proxy.example.net:" + proxyPort
							}
							if secure {
								uri += "?sni=proxy.example.net"
							}
							node, err := links.Parse(uri)
							if err != nil {
								t.Fatal(err)
							}
							if scenario == "custom-headers" {
								node["headers"] = Record{"User-Agent": "legacy-client/1", "X-Legacy-Route": "literal-{{.Target}}"}
							}
							if scenario == "explicit-insecure" {
								node["skip-cert-verify"] = true
							}
							if scenario == "wrong-sni" {
								node["sni"] = "wrong.example.net"
							}
							convert := NodeOutbound
							if kind == "sing-box" {
								convert = singRelayOutbound
							}
							out, err := convert(node, "proxy")
							if err != nil {
								t.Fatal(err)
							}
							listener, err := net.Listen("tcp", "127.0.0.1:0")
							if err != nil {
								t.Fatal(err)
							}
							port := listener.Addr().(*net.TCPAddr).Port
							listener.Close()
							var inbound Record
							if kind == "sing-box" {
								out["server"] = "127.0.0.1"
								inbound = Record{"type": "socks", "listen": "127.0.0.1", "listen_port": port}
								if secure && scenario != "untrusted-certificate" && scenario != "explicit-insecure" {
									out["tls"].(Record)["certificate_path"] = cert
								}
							} else {
								out["settings"].(Record)["servers"].([]any)[0].(Record)["address"] = "127.0.0.1"
								inbound = Record{"protocol": "socks", "listen": "127.0.0.1", "port": port, "settings": Record{"auth": "noauth"}}
								if secure && scenario != "untrusted-certificate" && scenario != "explicit-insecure" {
									out["streamSettings"].(Record)["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "usage": "verify"}}
								}
							}
							stop, coreLog := startSSFixtureCore(t, ctx, binary, kind, Record{"inbounds": []any{inbound}, "outbounds": []any{out}}, port)
							defer stop()
							socksURL, _ := url.Parse("socks5://127.0.0.1:" + value(port))
							transport := &http.Transport{Proxy: http.ProxyURL(socksURL)}
							defer transport.CloseIdleConnections()
							before := accepted.Load()
							response, requestErr := (&http.Client{Transport: transport, Timeout: 2 * time.Second}).Get(target.URL)
							var body []byte
							if response != nil {
								body, _ = io.ReadAll(response.Body)
								response.Body.Close()
							}
							if scenario == "success" || scenario == "explicit-insecure" || scenario == "custom-headers" {
								if requestErr != nil || string(body) != "http-connect-proof" || accepted.Load() <= before {
									output, _ := coreLog.result()
									t.Fatal("CONNECT failed", requestErr, output)
								}
							} else if requestErr == nil || accepted.Load() != before {
								t.Fatal("invalid auth or certificate allowed")
							}
						})
					}
				})
			}
		})
	}
}
