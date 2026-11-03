package web

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func attemptLogin(s *Server, password string) int {
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	return request(s, "POST", "/admin/api/login", string(body), "", "https://panel.test", true).Code
}

func TestLoginLimitSurvivesEachRestart(t *testing.T) {
	s := fixture(t)
	for i := 0; i < 5; i++ {
		if code := attemptLogin(s, "wrong"); code != http.StatusForbidden {
			t.Fatal(i, code)
		}
		s = reopen(t, s)
	}
	if code := attemptLogin(s, "long-test-password"); code != http.StatusTooManyRequests {
		t.Fatal("restart reset limiter", code)
	}
	value := authDocument(t, s)["goLoginFailures"].(map[string]any)
	entries := value["entries"].(map[string]any)
	for key := range entries {
		if len(key) != 64 || strings.Contains(key, "admin") || strings.Contains(key, "ip:") {
			t.Fatal("unhashed limiter key", key)
		}
	}
	// A fixed window expires even after restart; correct credentials then work.
	doc := authDocument(t, s)
	oldEntries := map[string]failure{}
	for key, v := range s.failures {
		v.Since = time.Now().Add(-loginFailureWindow - time.Second)
		oldEntries[key] = v
	}
	doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(s.account), Entries: oldEntries}
	writeAuthDocument(t, s, doc)
	s = reopen(t, s)
	if code := attemptLogin(s, "long-test-password"); code != 200 {
		t.Fatal("expired limiter blocked valid login", code)
	}
	s = reopen(t, s)
	if len(s.failures) != 0 {
		t.Fatal("successful login did not persist reset")
	}
}

func TestSuccessfulLoginResetsPersistentFailuresAndPreservesFields(t *testing.T) {
	s := fixture(t)
	doc := authDocument(t, s)
	doc["extension"] = "keep"
	writeAuthDocument(t, s, doc)
	for i := 0; i < 4; i++ {
		if code := attemptLogin(s, "wrong"); code != 403 {
			t.Fatal(code)
		}
	}
	if code := attemptLogin(s, "long-test-password"); code != 200 {
		t.Fatal(code)
	}
	s = reopen(t, s)
	if len(s.failures) != 0 || authDocument(t, s)["extension"] != "keep" {
		t.Fatal("failed to preserve state")
	}
	if code := attemptLogin(s, "wrong"); code != 403 {
		t.Fatal(code)
	}
	s = reopen(t, s)
	for _, v := range s.failures {
		if v.Count != 1 {
			t.Fatal("successful login retained failure count")
		}
	}
}

func TestLimiterDiskFailureStopsAdmission(t *testing.T) {
	s := fixture(t)
	s.options.AuthFile = s.options.Root
	if code := attemptLogin(s, "wrong"); code != 500 {
		t.Fatal("disk failure admitted password check", code)
	}
	if len(s.failures) != 0 {
		t.Fatal("uncommitted failure state published")
	}
}

func TestMalformedPersistentLimiterRejected(t *testing.T) {
	for _, bad := range []any{
		nil,
		map[string]any{"version": 2, "credential": "bad", "entries": map[string]any{}},
		savedLoginFailures{Version: 1, Credential: "bad", Entries: nil},
	} {
		t.Run("bad", func(t *testing.T) {
			s := fixture(t)
			doc := authDocument(t, s)
			doc["goLoginFailures"] = bad
			writeAuthDocument(t, s, doc)
			if _, err := New(s.options); err == nil {
				t.Fatal("malformed limiter accepted")
			}
		})
	}
	s := fixture(t)
	doc := authDocument(t, s)
	doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(s.account), Entries: map[string]failure{failureKey("ip:test"): {Count: 6, Since: time.Now()}}}
	writeAuthDocument(t, s, doc)
	if _, err := New(s.options); err == nil {
		t.Fatal("invalid attempt count accepted")
	}
	// A crash before a successful password check leaves the reservation durable.
	doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(s.account), Entries: map[string]failure{failureKey("account:admin"): {Count: 5, Since: time.Now()}}}
	writeAuthDocument(t, s, doc)
	next := reopen(t, s)
	if code := attemptLogin(next, "long-test-password"); code != 429 {
		t.Fatal("crash reservation lost", code)
	}
	data, _ := os.ReadFile(s.options.AuthFile)
	if strings.Contains(string(data), "wrong") {
		t.Fatal("password written into limiter")
	}
}
