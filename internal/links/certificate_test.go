package links

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestEmbeddedCertificatePinRoundTrip(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"tls.example"}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	digest := sha256.Sum256(der)
	compact := strings.ToUpper(hex.EncodeToString(digest[:]))
	for _, scheme := range []string{"hysteria2", "tuic"} {
		for _, key := range []string{"tls_certificate", "tls-certificate"} {
			for _, body := range []string{cert, strings.ReplaceAll(strings.TrimSpace(cert), "\n", ",")} {
				q := url.Values{key: {body}, "sni": {"tls.example"}}
				node, err := Parse(scheme + "://id:password@example.net:443?" + q.Encode())
				if err != nil {
					t.Fatal(err)
				}
				if strings.ReplaceAll(node["fingerprint"].(string), ":", "") != compact {
					t.Fatal("certificate hash changed")
				}
				uri, err := Export(node)
				if err != nil {
					t.Fatal(err)
				}
				restored, err := Parse(uri)
				if err != nil || restored["fingerprint"] != node["fingerprint"] {
					t.Fatal("share lost certificate pin", err)
				}
				q.Set("pinSHA256", strings.Repeat("00", 32))
				if scheme == "tuic" {
					q.Del("pinSHA256")
					q.Set("pinned_certchain_sha256", strings.Repeat("00", 32))
				}
				if _, err := Parse(scheme + "://id:password@example.net:443?" + q.Encode()); err == nil {
					t.Fatal("conflicting certificate and pin accepted")
				}
			}
		}
	}
	for _, bad := range []string{"", "private-secret", cert + cert, cert + "trailing", strings.Replace(cert, "CERTIFICATE", "PRIVATE KEY", 2), "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----"} {
		if _, err := certificatePin(bad); err == nil || strings.Contains(err.Error(), "private-secret") {
			t.Fatal("malformed certificate accepted or leaked")
		}
	}
}

func TestCertificatePinValidationAndLossyExportGuard(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	for _, query := range []string{"pinSHA256=" + pin + "&tls=false", "pinSHA256=", "pinSHA256=abc", "pinSHA256=" + pin + "&pinSHA256=" + pin, "pinned_certchain_sha256=" + pin} {
		if _, err := Parse("hysteria2://secret@example.net:443?" + query); err == nil {
			t.Fatal("invalid pin accepted", query)
		}
	}
	for _, kind := range []string{"vless", "vmess", "trojan", "ss", "http", "socks5", "snell"} {
		node := map[string]any{"type": kind, "server": "example.net", "port": 443, "fingerprint": pin}
		if _, err := Export(node); err == nil {
			t.Fatalf("%s silently dropped certificate pin", kind)
		}
		if _, err := Parse(kind + "://id:secret@example.net:443?pinSHA256=" + pin); err == nil {
			t.Fatalf("%s accepted HY2 pin", kind)
		}
	}
	for _, bad := range []any{true, 12, "", strings.Repeat("g", 64), strings.Repeat("a", 63), strings.Repeat("ab:", 31) + "a"} {
		if _, err := Export(map[string]any{"type": "hysteria2", "server": "example.net", "port": 443, "password": "secret", "fingerprint": bad}); err == nil {
			t.Fatal("invalid fingerprint exported")
		}
	}
}

func TestPythonTUICPinAndInsecureAlias(t *testing.T) {
	pin := strings.Repeat("ab", 32)
	node, err := Parse("tuic://id:secret@example.net:443?pinned_certchain_sha256=" + pin + "&allow_insecure=1")
	if err != nil || node["skip-cert-verify"] != true || node["fingerprint"] == nil {
		t.Fatal("Python TUIC link rejected", err)
	}
	for _, query := range []string{"allow_insecure=1&insecure=0", "allowInsecure=0&insecure=1", "allow_insecure=1&allowInsecure=0"} {
		if _, err := Parse("tuic://id:secret@example.net:443?" + query); err == nil {
			t.Fatal("ambiguous TLS verification accepted")
		}
	}
}
