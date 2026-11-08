package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

func TestBootstrapUnicodeCredentialRulesAndNoOverwrite(t *testing.T) {
	root := t.TempDir()
	auth := filepath.Join(root, "auth.json")
	for _, tc := range []struct{ username, password string }{
		{"管理员", strings.Repeat("界", 4)},
		{"界界", "long-test-password"},
		{"bad:name", "long-test-password"},
		{"bad name", "long-test-password"},
		{"admin", string([]byte{0xff}) + "long-test-password"},
	} {
		if err := bootstrap(root, auth, tc.username, strings.NewReader(tc.password)); err == nil {
			t.Fatal("invalid credentials accepted")
		}
		if _, err := os.Stat(auth); !os.IsNotExist(err) {
			t.Fatal("rejected bootstrap created credentials")
		}
	}
	username, password := strings.Repeat("界", 64), strings.Repeat("密", 12)
	if err := bootstrap(root, auth, username, strings.NewReader(password+"\n")); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(auth)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Username, Salt, Hash string
		Iterations           int
	}
	if err = json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Username != username || !legacycrypto.VerifyPassword(password, doc.Salt, doc.Hash, doc.Iterations) {
		t.Fatal("Unicode credential did not round trip")
	}
	if err := bootstrap(root, auth, "admin", strings.NewReader("another-password")); err == nil {
		t.Fatal("existing credentials overwritten")
	}
	after, err := os.ReadFile(auth)
	if err != nil || string(after) != string(raw) {
		t.Fatal("failed bootstrap changed credentials", err)
	}
}
