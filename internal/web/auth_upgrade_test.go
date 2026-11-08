package web

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

func TestLegacyLoginUpgradesWithoutLosingSessionsOrOtherLimits(t *testing.T) {
	s := fixture(t)
	oldToken := login(t, s)
	auth := s.account
	salt, _ := hex.DecodeString(auth.Salt)
	hash, err := pbkdf2.Key(sha256.New, "long-test-password", salt, 240000, 32)
	if err != nil {
		t.Fatal(err)
	}
	auth.Hash, auth.Iterations = hex.EncodeToString(hash), 240000
	doc := authDocument(t, s)
	doc["hash"], doc["iterations"] = auth.Hash, auth.Iterations
	doc["goSessions"] = encodeSessions(auth, s.sessions)
	unrelated := failureKey("account:other")
	doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(auth), Entries: map[string]failure{unrelated: {Count: 4, Since: s.now()}}}
	doc["extension"] = "preserved"
	writeAuthDocument(t, s, doc)
	s = reopen(t, s)
	newToken := login(t, s)
	if s.account.Iterations != 600000 || s.account.Hash == auth.Hash || !legacycrypto.VerifyPassword("long-test-password", s.account.Salt, s.account.Hash, s.account.Iterations) {
		t.Fatal("legacy hash not upgraded")
	}
	s = reopen(t, s)
	for _, token := range []string{oldToken, newToken} {
		if w := request(s, "GET", "/admin/api/account", "", token, "", true); w.Code != 200 {
			t.Fatal("upgrade revoked session", w.Code)
		}
	}
	if s.failures[unrelated].Count != 4 || len(s.failures) != 1 {
		t.Fatal("upgrade lost unrelated rate limits", s.failures)
	}
	if authDocument(t, s)["extension"] != "preserved" {
		t.Fatal("extension lost")
	}
}

func TestLoginTransactionRejectsChangedDiskWithoutPublishing(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	before := s.account
	doc := authDocument(t, s)
	doc["salt"] = strings.Repeat("a", 32)
	writeAuthDocument(t, s, doc)
	s.mu.Lock()
	err := s.completeLogin(before, before, nil, sha256.Sum256([]byte("new-token")))
	s.mu.Unlock()
	if err == nil || s.account != before || len(s.sessions) != 1 {
		t.Fatal("conflicting write published state")
	}
	if _, ok := s.sessions[sha256.Sum256([]byte(token))]; !ok {
		t.Fatal("old session lost")
	}
	if authDocument(t, s)["salt"] != doc["salt"] {
		t.Fatal("external change overwritten")
	}
}

func TestAccountUnicodeAndPythonUsernameRules(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, name := range []string{"   ", "ab", "bad:name", "bad name", "bad\u2003name", strings.Repeat("界", 65)} {
		data, _ := json.Marshal(map[string]string{"current": "long-test-password", "newUsername": name})
		if w := request(s, "POST", "/admin/api/account", string(data), token, "https://panel.test", true); w.Code != 400 {
			t.Fatal(name, w.Code, w.Body.String())
		}
	}
	name := strings.Repeat("界", 64)
	data, _ := json.Marshal(map[string]string{"current": "long-test-password", "newUsername": name, "newPassword": strings.Repeat("界", 4)})
	if w := request(s, "POST", "/admin/api/account", string(data), token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("password bytes counted as characters", w.Code)
	}
	data, _ = json.Marshal(map[string]string{"current": "long-test-password", "newUsername": name})
	if w := request(s, "POST", "/admin/api/account", string(data), token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	data, _ = json.Marshal(map[string]string{"username": name, "password": "long-test-password"})
	if w := request(reopen(t, s), "POST", "/admin/api/login", string(data), "", "https://panel.test", true); w.Code != 200 {
		t.Fatal("unicode username cannot login", w.Code, w.Body.String())
	}
}
