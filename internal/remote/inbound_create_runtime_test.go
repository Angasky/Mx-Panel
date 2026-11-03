package remote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func templateTestCertificate(t *testing.T, domain string, expired bool) (string, string) {
	t.Helper()
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	until := time.Now().Add(time.Hour)
	if expired {
		until = time.Now().Add(-time.Minute)
	}
	cert := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: domain}, DNSNames: []string{domain}, NotBefore: time.Now().Add(-time.Hour), NotAfter: until, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &private.PublicKey, private)
	if err != nil {
		t.Fatal(err)
	}
	key, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	certFile, keyFile := filepath.Join(root, "fullchain.pem"), filepath.Join(root, "private.pem")
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600); err != nil {
		t.Fatal(err)
	}
	return filepath.ToSlash(certFile), filepath.ToSlash(keyFile)
}

func TestTemplateCertificateScriptWithRealOpenSSL(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		bash = "C:/Program Files/Git/bin/bash.exe"
	}
	if err = exec.Command(bash, "-c", "command -v openssl").Run(); err != nil {
		t.Skip("Bash/OpenSSL unavailable")
	}
	cert, key := templateTestCertificate(t, "node.example.com", false)
	_, wrong := templateTestCertificate(t, "node.example.com", false)
	expired, expiredKey := templateTestCertificate(t, "node.example.com", true)
	panel := &Panel{run: func(ctx context.Context, script string, limit int) (string, error) {
		command := exec.CommandContext(ctx, bash, "-s")
		command.Stdin = strings.NewReader(script)
		raw, err := command.CombinedOutput()
		return string(raw), err
	}}
	for _, row := range []struct {
		cert, key, domain string
		good              bool
	}{{cert, key, "node.example.com", true}, {cert, wrong, "node.example.com", false}, {cert, key, "other.example.com", false}, {expired, expiredKey, "node.example.com", false}} {
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		err = validateTemplateCertificate(ctx, panel, Record{"template": "hysteria2", "serverName": row.domain, "certFile": row.cert, "keyFile": row.key})
		cancel()
		if (err == nil) != row.good {
			t.Fatal("certificate verification mismatch", row.good, err)
		}
	}
}

func TestNativeInboundTemplatesAcceptedByRealXray(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary == "" {
		t.Skip("set MXIOC_TEST_XRAY for template validation")
	}
	cert, key := templateTestCertificate(t, "node.example.com", false)
	for _, name := range []string{"vless-reality", "vmess-tcp", "trojan-tls", "vless-ws-tls", "hysteria2"} {
		t.Run(name, func(t *testing.T) {
			row, err := buildInboundTemplate(Record{"template": name, "serverName": "node.example.com", "certFile": "/fixture/fullchain.pem", "keyFile": "/fixture/private.pem", "port": 24001}, "1.1.1.1")
			if err != nil {
				t.Fatal(err)
			}
			row["listen"] = "127.0.0.1"
			if tlsTemplate(name) {
				row["streamSettings"].(Record)["tlsSettings"].(Record)["certificates"] = []any{Record{"certificateFile": cert, "keyFile": key}}
			}
			raw, _ := json.Marshal(Record{"inbounds": []any{row}, "outbounds": []any{Record{"protocol": "blackhole"}}})
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			command := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
			command.Stdin = strings.NewReader(string(raw))
			if output, err := command.CombinedOutput(); err != nil {
				t.Fatal("generated template rejected", err, string(output))
			}
		})
	}
}

// Optional isolated protocol test: an actual Xray HY2 server and client, only
// loopback listeners, local test certificates and HTTP blackhole proof.
func TestNativeHY2TemplateWithRealXray(t *testing.T) {
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary == "" {
		t.Skip("set MXIOC_TEST_XRAY for real HY2 verification")
	}
	cert, key := templateTestCertificate(t, "node.example.com", false)
	ctx, cancel := context.WithTimeout(context.Background(), 35*time.Second)
	defer cancel()
	start := func(config Record, port int) (func(), *capture) {
		raw, _ := json.Marshal(config)
		check := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
		check.Stdin = strings.NewReader(string(raw))
		if output, err := check.CombinedOutput(); err != nil {
			t.Fatal("Xray rejected native template", err, string(output))
		}
		command := exec.CommandContext(ctx, binary, "run", "-config", "stdin:")
		command.Stdin = strings.NewReader(string(raw))
		output := &capture{limit: 64 << 10}
		command.Stdout = output
		command.Stderr = output
		if err := command.Start(); err != nil {
			t.Fatal(err)
		}
		stop := func() { command.Process.Kill(); command.Wait() }
		t.Cleanup(func() {
			if command.ProcessState == nil {
				stop()
			}
		})
		if port > 0 {
			deadline := time.Now().Add(3 * time.Second)
			ready := false
			for time.Now().Before(deadline) {
				conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", value(port)), 50*time.Millisecond)
				if err == nil {
					conn.Close()
					ready = true
					break
				}
				time.Sleep(20 * time.Millisecond)
			}
			if !ready {
				log, _ := output.result()
				t.Fatal("local client did not listen", log)
			}
		} else {
			time.Sleep(120 * time.Millisecond)
		}
		return stop, output
	}
	for _, allowed := range []bool{false, true, false} {
		packet, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := packet.LocalAddr().(*net.UDPAddr).Port
		packet.Close()
		// Build using normal absolute Linux paths, then substitute local test files.
		row, err := buildInboundTemplate(Record{"template": "hysteria2", "serverName": "node.example.com", "certFile": "/fixture/fullchain.pem", "keyFile": "/fixture/key.pem", "port": port}, "")
		if err != nil {
			t.Fatal(err)
		}
		row["listen"] = "127.0.0.1"
		tls := row["streamSettings"].(Record)["tlsSettings"].(Record)
		tls["certificates"] = []any{Record{"certificateFile": cert, "keyFile": key}}
		user, err := NewUser(row)
		if err != nil {
			t.Fatal(err)
		}
		if allowed {
			row["settings"].(Record)["clients"] = []any{user}
		}
		serverStop, serverLog := start(Record{"log": Record{"loglevel": "error"}, "inbounds": []any{row}, "outbounds": []any{Record{"protocol": "blackhole", "settings": Record{"response": Record{"type": "http"}}}}}, 0)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		socks := listener.Addr().(*net.TCPAddr).Port
		listener.Close()
		client := Record{"log": Record{"loglevel": "error"}, "inbounds": []any{Record{"listen": "127.0.0.1", "port": socks, "protocol": "socks", "settings": Record{"auth": "noauth"}}}, "outbounds": []any{Record{"protocol": "hysteria", "settings": Record{"version": 2, "address": "127.0.0.1", "port": port}, "streamSettings": Record{"network": "hysteria", "security": "tls", "hysteriaSettings": Record{"version": 2, "auth": user["auth"]}, "tlsSettings": Record{"serverName": "node.example.com", "certificates": []any{Record{"certificateFile": cert, "usage": "verify"}}, "alpn": []any{"h3"}}}}}}
		clientStop, clientLog := start(client, socks)
		proxy, _ := url.Parse("socks5://" + net.JoinHostPort("127.0.0.1", value(socks)))
		transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
		response, err := (&http.Client{Transport: transport, Timeout: 3 * time.Second}).Head("http://hy2-template-proof.invalid/")
		passed := err == nil && response.StatusCode == 403
		if response != nil {
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
		}
		transport.CloseIdleConnections()
		clientStop()
		serverStop()
		if passed != allowed {
			a, _ := serverLog.result()
			b, _ := clientLog.result()
			t.Fatal("HY2 authentication mismatch", allowed, err, a, b)
		}
	}
	t.Log("real HY2: empty clients denied; owned auth connected; empty clients denied again; all traffic loopback")
}
