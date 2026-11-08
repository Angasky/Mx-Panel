package web

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

func reopen(t *testing.T, s *Server) *Server {
	t.Helper()
	next, err := New(s.options)
	if err != nil {
		t.Fatal(err)
	}
	return next
}
func authDocument(t *testing.T, s *Server) map[string]any {
	t.Helper()
	data, err := os.ReadFile(s.options.AuthFile)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if json.Unmarshal(data, &doc) != nil {
		t.Fatal("bad credential document")
	}
	return doc
}
func writeAuthDocument(t *testing.T, s *Server, doc map[string]any) {
	t.Helper()
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(s.options.AuthFile, data, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestPersistentSessionRestartLogoutAndCredentialChange(t *testing.T) {
	s := fixture(t)
	doc := authDocument(t, s)
	doc["extension"] = map[string]any{"keep": "unchanged"}
	writeAuthDocument(t, s, doc)
	token := login(t, s)
	data, _ := os.ReadFile(s.options.AuthFile)
	if strings.Contains(string(data), token) {
		t.Fatal("plaintext session stored")
	}
	next := reopen(t, s)
	if w := request(next, "GET", "/admin/api/account", "", token, "", true); w.Code != 200 {
		t.Fatal("restart lost login", w.Code)
	}
	if w := request(next, "POST", "/admin/api/logout", "{}", token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	next = reopen(t, next)
	if w := request(next, "GET", "/admin/api/account", "", token, "", true); w.Code != 401 {
		t.Fatal("logout undone by restart")
	}
	token = login(t, next)
	if w := request(next, "POST", "/admin/api/account", `{"current":"long-test-password","newPassword":"another-test-password","newUsername":"new-admin"}`, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	next = reopen(t, next)
	if w := request(next, "GET", "/admin/api/account", "", token, "", true); w.Code != 401 {
		t.Fatal("password change resurrected session")
	}
	if authDocument(t, next)["extension"].(map[string]any)["keep"] != "unchanged" {
		t.Fatal("session persistence discarded extension")
	}
}

func TestSessionPersistenceFailuresDoNotPublishSuccess(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	saved := s.options.AuthFile
	s.options.AuthFile = s.options.Root // a directory, deterministically rejects IO
	defer func() { s.options.AuthFile = saved }()
	if w := request(s, "POST", "/admin/api/login", `{"username":"admin","password":"long-test-password"}`, "", "https://panel.test", true); w.Code != 500 || len(w.Result().Cookies()) != 0 {
		t.Fatal("failed login write published session", w.Code)
	}
	if len(s.sessions) != 1 {
		t.Fatal("failed login changed memory")
	}
	if w := request(s, "POST", "/admin/api/logout", "{}", token, "https://panel.test", true); w.Code != 500 {
		t.Fatal("failed logout write reported success")
	}
	if w := request(s, "GET", "/admin/api/account", "", token, "", true); w.Code != 200 {
		t.Fatal("failed logout diverged from disk")
	}
}

func TestSessionCredentialGenerationExpiryAndInvalidData(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	doc := authDocument(t, s)
	salt, digest, err := legacycrypto.NewPassword("external-password-change")
	if err != nil {
		t.Fatal(err)
	}
	doc["salt"], doc["hash"], doc["iterations"] = salt, digest, 600000
	writeAuthDocument(t, s, doc)
	next := reopen(t, s)
	if len(next.sessions) != 0 {
		t.Fatal("changed credentials adopted old sessions")
	}
	if w := request(next, "GET", "/admin/api/account", "", token, "", true); w.Code != 401 {
		t.Fatal("credential generation bypassed")
	}
	now := time.Now()
	entry := session{Created: now.Add(-13 * time.Hour), Expires: now.Add(-time.Hour)}
	key := sha256.Sum256([]byte(token))
	doc["goSessions"] = encodeSessions(next.account, map[[32]byte]session{key: entry})
	writeAuthDocument(t, next, doc)
	if len(reopen(t, next).sessions) != 0 {
		t.Fatal("expired sessions restored")
	}
	entry.Created = now
	entry.Expires = now.Add(48 * time.Hour)
	doc["goSessions"] = encodeSessions(next.account, map[[32]byte]session{key: entry})
	writeAuthDocument(t, next, doc)
	if _, err = New(next.options); err == nil {
		t.Fatal("unbounded session lifetime accepted")
	}
}

func TestSessionCapAndCookieLogout(t *testing.T) {
	s := fixture(t)
	now := time.Now()
	entries := map[[32]byte]session{}
	var oldest [32]byte
	for i := 0; i < sessionLimit; i++ {
		key := sha256.Sum256([]byte{byte(i)})
		if i == 0 {
			oldest = key
		}
		stamp := now.Add(time.Duration(i-sessionLimit) * time.Minute)
		entries[key] = session{Created: stamp, Expires: stamp.Add(sessionTTL)}
	}
	doc := authDocument(t, s)
	doc["goSessions"] = encodeSessions(s.account, entries)
	writeAuthDocument(t, s, doc)
	s = reopen(t, s)
	token := login(t, s)
	if len(s.sessions) != sessionLimit {
		t.Fatal("session cap ignored")
	}
	if _, exists := s.sessions[oldest]; exists {
		t.Fatal("oldest session not evicted")
	}
	r := httptest.NewRequest("POST", "https://panel.test/admin/api/logout", strings.NewReader("{}"))
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.test")
	r.Header.Set("Authorization", "Basic unrelated")
	r.AddCookie(&http.Cookie{Name: "mxioc_session", Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	next := reopen(t, s)
	if w = request(next, "GET", "/admin/api/account", "", token, "", true); w.Code != 401 {
		t.Fatal("cookie logout failed with unrelated authorization header")
	}
}

func TestPythonBearerWhitespaceAndExplicitHeaderPrecedence(t *testing.T) {
	for _, tc := range []struct{ header, want string }{
		{"Bearer   token-with-padding  ", "token-with-padding"},
		{"Bearer ", ""},
		{"Bearer bad-token", "bad-token"},
		{"Basic ignored", "cookie-token"},
	} {
		r := httptest.NewRequest("GET", "https://panel.test/admin/api/account", nil)
		r.Header.Set("Authorization", tc.header)
		r.AddCookie(&http.Cookie{Name: "mxioc_session", Value: "cookie-token"})
		if got := requestSessionToken(r); got != tc.want {
			t.Fatalf("header precedence: got %q want %q", got, tc.want)
		}
	}
}
