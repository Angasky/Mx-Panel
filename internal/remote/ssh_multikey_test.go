package remote

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func TestPinnedSSHMatchesLegacyKeyWithoutAuthenticatingOtherKeys(t *testing.T) {
	ec, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecSigner, err := ssh.NewSignerFromKey(ec)
	if err != nil {
		t.Fatal(err)
	}
	rsaSigner, err := ssh.NewSignerFromKey(rsaKey)
	if err != nil {
		t.Fatal(err)
	}
	c, authCalls := sshFixture(t, ecSigner, rsaSigner)
	// Legacy Ed25519 and existing Go ECDSA pins must both match on a multi-key host.
	client, err := Connect(context.Background(), c)
	if err != nil {
		t.Fatal("legacy Ed25519 pin", err)
	}
	client.Close()
	if authCalls.Load() != 1 {
		t.Fatal("password reached a mismatched key", authCalls.Load())
	}
	bad := c
	bad.Password = "wrong-password"
	if _, err = Connect(context.Background(), bad); err == nil {
		t.Fatal("wrong password accepted")
	}
	if authCalls.Load() != 2 {
		t.Fatal("retried password authentication", authCalls.Load())
	}
	c.Fingerprint = ssh.FingerprintSHA256(ecSigner.PublicKey())
	client, err = Connect(context.Background(), c)
	if err != nil {
		t.Fatal("existing Go ECDSA pin", err)
	}
	client.Close()
	if authCalls.Load() != 3 {
		t.Fatal("ECDSA authentication count", authCalls.Load())
	}
	bad = c
	bad.Password = "wrong-password"
	if _, err = Connect(context.Background(), bad); err == nil || !strings.Contains(err.Error(), "认证失败") {
		t.Fatal("matching fallback key was mislabeled as a fingerprint change", err)
	}
	if authCalls.Load() != 4 {
		t.Fatal("fallback retried password authentication", authCalls.Load())
	}
	c.Fingerprint = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	if _, err = Connect(context.Background(), c); err == nil {
		t.Fatal("unknown fingerprint accepted")
	}
	if authCalls.Load() != 4 {
		t.Fatal("password sent to an unknown host key")
	}
}
