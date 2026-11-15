package netprobe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// TLSResult describes an ordinary TLS handshake, never proxy authentication.
type TLSResult struct {
	Result
	TLSOK              bool     `json:"tlsOK"`
	TLSError           string   `json:"tlsError,omitempty"`
	TLSMilliseconds    *float64 `json:"tlsMilliseconds"`
	CertificateExpires int64    `json:"certificateExpires,omitempty"`
	TLSVersion         string   `json:"tlsVersion,omitempty"`
}
type TLSTarget struct {
	Target
	ServerName string
	ALPN       []string
}

func validTLSTarget(t TLSTarget) bool {
	if Validate([]Target{t.Target}) != nil || t.Method != "tcp" || t.ServerName == "" || len(t.ServerName) > 253 || strings.ContainsAny(t.ServerName, "/\\@%") || strings.ContainsFunc(t.ServerName, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) || len(t.ALPN) > 16 {
		return false
	}
	for _, p := range t.ALPN {
		if len(p) == 0 || len(p) > 255 || strings.ContainsFunc(p, unicode.IsControl) {
			return false
		}
	}
	return true
}
func MeasureTLS(parent context.Context, targets []TLSTarget) []TLSResult {
	if len(targets) > 6 {
		return nil
	}
	results := make([]TLSResult, len(targets))
	done := make(chan struct{}, len(targets))
	for i, t := range targets {
		go func(i int, t TLSTarget) {
			defer func() { done <- struct{}{} }()
			ctx, cancel := context.WithTimeout(parent, 5*time.Second)
			defer cancel()
			results[i] = measureTLS(ctx, t, net.DefaultResolver.LookupIPAddr, (&net.Dialer{}).DialContext, nil)
		}(i, t)
	}
	for range targets {
		<-done
	}
	return results
}
func measureTLS(ctx context.Context, t TLSTarget, lookup func(context.Context, string) ([]net.IPAddr, error), dial func(context.Context, string, string) (net.Conn, error), roots *x509.CertPool) TLSResult {
	r := TLSResult{Result: Result{Name: t.Name, Time: time.Now().Unix(), Method: "tcp"}}
	if !validTLSTarget(t) {
		r.Error = "invalid-target"
		return r
	}
	addresses, err := lookup(ctx, strings.Trim(t.Host, "[]"))
	if err != nil || len(addresses) == 0 {
		r.Error = "dns-failed"
		return r
	}
	for _, a := range addresses {
		if !publicIP(a.IP) || a.Zone != "" {
			r.Error = "blocked-address"
			return r
		}
	}
	var conn net.Conn
	for i, a := range addresses {
		if ctx.Err() != nil {
			break
		}
		// Reserve time for other address families rather than exhausting the entire
		// deadline on an unreachable first address.
		remaining := 3 * time.Second
		if deadline, ok := ctx.Deadline(); ok {
			remaining = time.Until(deadline)
		}
		budget := remaining / time.Duration(len(addresses)-i+1)
		if budget > time.Second {
			budget = time.Second
		}
		attempt, cancel := context.WithTimeout(ctx, budget)
		start := time.Now()
		r.Sent = true
		conn, err = dial(attempt, "tcp", net.JoinHostPort(a.IP.String(), strconv.Itoa(t.Port)))
		cancel()
		if err == nil {
			ms := float64(time.Since(start).Microseconds()) / 1000
			r.Milliseconds = &ms
			r.OK = true
			break
		}
	}
	if conn == nil || err != nil {
		r.Error = "connect-failed"
		return r
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	client := tls.Client(conn, &tls.Config{ServerName: t.ServerName, NextProtos: t.ALPN, MinVersion: tls.VersionTLS12, RootCAs: roots})
	start := time.Now()
	err = client.HandshakeContext(ctx)
	if err != nil {
		var hostname x509.HostnameError
		var authority x509.UnknownAuthorityError
		var invalid x509.CertificateInvalidError
		var network net.Error
		switch {
		case errors.As(err, &hostname):
			r.TLSError = "certificate-hostname"
		case errors.As(err, &authority):
			r.TLSError = "certificate-untrusted"
		case errors.As(err, &invalid):
			if invalid.Reason == x509.Expired {
				r.TLSError = "certificate-expired"
			} else {
				r.TLSError = "certificate-invalid"
			}
		case ctx.Err() != nil || errors.As(err, &network) && network.Timeout():
			r.TLSError = "tls-timeout"
		default:
			r.TLSError = "tls-handshake"
		}
		return r
	}
	state := client.ConnectionState()
	ms := float64(time.Since(start).Microseconds()) / 1000
	r.TLSOK = true
	r.TLSMilliseconds = &ms
	r.TLSVersion = tls.VersionName(state.Version)
	if len(state.PeerCertificates) > 0 {
		r.CertificateExpires = state.PeerCertificates[0].NotAfter.Unix()
	}
	return r
}
