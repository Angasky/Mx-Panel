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

func TestMalformedReferencesNeverAuthorizeLegacyCleanup(t *testing.T) {
	node := map[string]any{"name": "owned", "type": "vless", "port": 443, "uuid": "uuid"}
	hash, err := remote.UserIdentity(map[string]any{"id": "uuid", "email": "owner"})
	if err != nil {
		t.Fatal(err)
	}
	binding := map[string]any{"scope": "user", "port": 443, "userHash": hash, "userEmail": "owner"}
	for _, refs := range []any{
		"corrupt", true, 1, map[string]any{"identity": Identity(node)},
		[]any{"corrupt"}, []any{map[string]any{"identity": "different"}},
	} {
		binding["importedNodes"] = refs
		if Owns(binding, node) {
			t.Fatal("invalid evidence activated legacy deletion", refs)
		}
	}
	binding["importedNodes"] = []any{map[string]any{"name": "old name", "identity": Identity(node)}}
	node["name"] = "renamed"
	if !Owns(binding, node) {
		t.Fatal("rename invalidated credential proof")
	}
	node["uuid"] = "another-user"
	if Owns(binding, node) {
		t.Fatal("changed credential retained ownership")
	}
}

func TestLegacyOwnershipAllSupportedCredentials(t *testing.T) {
	for _, kind := range []string{"vless", "vmess", "tuic", "trojan", "hysteria2"} {
		for _, useAuth := range []bool{false, true} {
			if useAuth && kind != "hysteria2" {
				continue
			}
			node := map[string]any{"type": kind, "port": 443, "uuid": "uuid", "password": "password", "flow": "xtls-rprx-vision"}
			client := map[string]any{"email": "owner", "flow": ""}
			if kind == "vless" || kind == "vmess" || kind == "tuic" {
				client["id"] = "uuid"
			}
			if kind == "trojan" || kind == "hysteria2" || kind == "tuic" {
				if useAuth {
					client["auth"] = "password"
				} else {
					client["password"] = "password"
				}
			}
			hash, err := remote.UserIdentity(client)
			if err != nil {
				t.Fatal(err)
			}
			binding := map[string]any{"scope": "user", "port": 443, "userEmail": "owner", "userHash": hash}
			if !Owns(binding, node) {
				t.Fatal("legacy owner lost", kind, useAuth)
			}
			binding["userEmail"] = "other"
			if Owns(binding, node) {
				t.Fatal("different email authorized", kind)
			}
		}
	}
}
