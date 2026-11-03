package subsource

import (
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func localSourceClient(t *testing.T, targetURL string) *Client {
	t.Helper()
	c := NewClient()
	transport := c.http.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialPublic(ctx, address, func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}, func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(strings.TrimPrefix(targetURL, "https://"), "http://"))
		})
	}
	t.Cleanup(transport.CloseIdleConnections)
	return c
}

func TestNativeGzipRedirectLimitAndTLSVerification(t *testing.T) {
	var loopCount atomic.Int32
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "/gzip", 302)
		case "/loop":
			loopCount.Add(1)
			http.Redirect(w, r, "/loop", 302)
		case "/gzip":
			if r.Header.Get("Referer") != "" {
				t.Error("redirect leaked source query in Referer")
			}
			w.Header().Set("Content-Encoding", "gzip")
			out := gzip.NewWriter(w)
			out.Write([]byte("trojan://secret@host.example.com:443#A"))
			out.Close()
		case "/bomb":
			w.Header().Set("Content-Encoding", "gzip")
			out := gzip.NewWriter(w)
			chunk := []byte(strings.Repeat("x", 8192))
			for i := 0; i < 1025; i++ {
				if _, err := out.Write(chunk); err != nil {
					break
				}
			}
			out.Close()
		}
	}))
	defer origin.Close()
	c := localSourceClient(t, origin.URL)
	text, err := c.Fetch(context.Background(), "http://public.test/redirect?token=private")
	if err != nil || text != "trojan://secret@host.example.com:443#A" {
		t.Fatal(text, err)
	}
	if _, err = c.Fetch(context.Background(), "http://public.test/bomb"); err == nil {
		t.Fatal("decompressed size limit bypassed")
	}
	if _, err = c.Fetch(context.Background(), "http://public.test/loop"); err == nil || loopCount.Load() != 5 {
		t.Fatal("redirect count unbounded", err, loopCount.Load())
	}
	tlsOrigin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("untrusted certificate reached HTTP handler") }))
	defer tlsOrigin.Close()
	c = localSourceClient(t, tlsOrigin.URL)
	if _, err = c.Fetch(context.Background(), "https://public.test/sub"); err == nil {
		t.Fatal("TLS verification was disabled")
	}
}

func TestVerifiedAddressesAndDNSPinning(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1", "::ffff:127.0.0.1", "0.0.0.0", "169.254.169.254", "10.0.0.1", "172.16.1.1", "192.168.1.1", "100.64.1.1", "198.18.0.1", "203.0.113.1", "224.0.0.1", "240.0.0.1", "fc00::1", "fe80::1", "2001:db8::1", "64:ff9b::7f00:1", "2002:7f00:1::"} {
		if publicAddress(netip.MustParseAddr(ip)) {
			t.Fatal("nonpublic address accepted", ip)
		}
	}
	for _, ip := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		if !publicAddress(netip.MustParseAddr(ip)) {
			t.Fatal("public rejected", ip)
		}
	}
	lookups, dials := 0, 0
	lookup := func(context.Context, string, string) ([]netip.Addr, error) {
		lookups++
		if lookups > 1 {
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		}
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials++
		if address != "8.8.8.8:443" {
			t.Fatal("dial used unverified hostname", address)
		}
		return nil, errors.New("fixture")
	}
	if _, err := dialPublic(context.Background(), "public.test:443", lookup, dial); err == nil || lookups != 1 || dials != 1 {
		t.Fatal("DNS pinning failed", err, lookups, dials)
	}
	lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("10.0.0.1")}, nil
	}
	dials = 0
	if _, err := dialPublic(context.Background(), "mixed.test:443", lookup, dial); err == nil || dials != 0 {
		t.Fatal("mixed DNS answer reached network")
	}
}

type roundTrip func(*http.Request) (*http.Response, error)

func (f roundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestFetchLimitsUTF8AndRedaction(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		size       int64
		status     int
		bad        bool
	}{
		{"bom", "\ufeff  hy2://secret@host:443#A  ", -1, 200, false},
		{"utf8", string([]byte{255}), -1, 200, true},
		{"status", "token-secret", -1, 403, true},
		{"declared", "", MaxBytes + 1, 200, true},
		{"stream", strings.Repeat("x", MaxBytes+1), -1, 200, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := NewClient()
			c.http.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("User-Agent") != "Mxioc-Subscription-Importer/1.0" || req.URL.Query().Get("token") != "token-secret" {
					t.Fatal("request contract changed")
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header), ContentLength: tc.size, Request: req}, nil
			})
			text, err := c.Fetch(context.Background(), "https://public.test/sub?token=token-secret")
			if (err != nil) != tc.bad {
				t.Fatal(text, err)
			}
			if !tc.bad && text != "hy2://secret@host:443#A" {
				t.Fatal("BOM/whitespace changed", text)
			}
			if err != nil && strings.Contains(err.Error(), "token-secret") {
				t.Fatal("fetch error leaked token")
			}
		})
	}
	c := NewClient()
	c.http.Transport = roundTrip(func(req *http.Request) (*http.Response, error) { return nil, errors.New(req.URL.String()) })
	if _, err := c.Fetch(context.Background(), "https://public.test/sub?token=token-secret"); err == nil || strings.Contains(err.Error(), "token-secret") {
		t.Fatal("transport error exposed URL", err)
	}
	for _, value := range []string{"file:///etc/passwd", "ftp://public.test/a", "https://admin:secret@public.test/a", "https://public.test:99999/sub", "/sub"} {
		if _, err := c.Fetch(context.Background(), value); err == nil {
			t.Fatal("invalid source accepted", value)
		}
	}
}

func TestNativeRedirectDoesNotReachPrivateTarget(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer target.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL+"/secret", 302) }))
	defer origin.Close()
	c := NewClient()
	transport := c.http.Transport.(*http.Transport)
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		lookup := func(context.Context, string, string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
		}
		return dialPublic(ctx, address, lookup, func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, strings.TrimPrefix(origin.URL, "http://"))
		})
	}
	defer transport.CloseIdleConnections()
	if _, err := c.Fetch(context.Background(), "http://public.test/sub?token=secret"); err == nil || hits.Load() != 0 {
		t.Fatal("redirect bypassed address validation", err, hits.Load())
	}
}

func TestCancellationAndLoopbackBlocked(t *testing.T) {
	c := NewClient()
	var hits atomic.Int32
	local := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer local.Close()
	if _, err := c.Fetch(context.Background(), local.URL); err == nil || hits.Load() != 0 {
		t.Fatal("private origin reached")
	}
	c.http.Transport = roundTrip(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if _, err := c.Fetch(ctx, "http://public.test/sub"); err == nil {
		t.Fatal("cancellation ignored")
	}
}
