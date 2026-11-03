package managednodes

import (
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"testing"
)

func TestPythonCompatibleIdentityAndLegacyUserProof(t *testing.T) {
	for _, tc := range []struct{ psk, hash string }{
		{"秘密+a/b@<>\\u2028", "e7d7ab05c5ecd47fb48af0cd64466d01c9217328b83f5f8f603efb411a8974c5"},
		{"秘密+a/b@<>\u2028", "3f4bcf8a00e7ea4c24d00092dc214dd2d45ecc4fb54a3e289672ab26da816041"},
	} {
		n := map[string]any{"type": "snell", "server": "node.example.com", "port": 24443, "psk": tc.psk}
		if Identity(n) != tc.hash {
			t.Fatal("Python node fingerprint mismatch")
		}
	}
	hash, err := remote.UserIdentity(map[string]any{"id": "uuid", "email": "owner"})
	if err != nil {
		t.Fatal(err)
	}
	b := map[string]any{"scope": "user", "userEmail": "owner", "userHash": hash, "port": 24443}
	n := map[string]any{"name": "renamed", "type": "vless", "port": 24443, "uuid": "uuid"}
	if !Owns(b, n) {
		t.Fatal("legacy user binding not recognized")
	}
	n["uuid"] = "new-user"
	if Owns(b, n) {
		t.Fatal("reused local name/port authorized deletion")
	}
}
