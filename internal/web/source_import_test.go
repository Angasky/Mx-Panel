package web

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func sourceRequest(s *Server, profile, path, body, token string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://panel.test/admin/api/"+path, strings.NewReader(body))
	r.TLS = &tls.ConnectionState{}
	r.RemoteAddr = "127.0.0.1:2222"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.test")
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Profile", profile)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}

const sourceFixtureText = `proxies:
 - {name: HY, type: hy2, server: hy.example.com, port: 24443, password: unique-secret, sni: hy.example.com}
 - {name: Snell, type: snell, server: snell.example.com, port: 24443, psk: snell-secret, version: 5, udp: true}
 - {name: bad, type: unsupported, server: bad.example.com, port: 1}
`

func TestSourcePreviewImportProfileAndRestart(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	profile, err := s.repository.CreateProfile(config.Document{"name": "Destination", "templateId": "blank"})
	if err != nil {
		t.Fatal(err)
	}
	id := profile["id"].(string)
	if err = s.repository.Mutate(id, func(d config.Document) error {
		d["proxy-groups"] = []any{config.Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	s.fetchSubscription = func(ctx context.Context, url string) (string, error) {
		calls.Add(1)
		if url != "https://public.test/sub?token=private" {
			t.Fatal(url)
		}
		return sourceFixtureText, nil
	}
	body := `{"url":"https://public.test/sub?token=private"}`
	w := sourceRequest(s, id, "import-subscription/preview", body, token)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var preview struct {
		Total     int
		Protocols map[string]int
		Skipped   []string
		Groups    []string
	}
	if json.Unmarshal(w.Body.Bytes(), &preview) != nil || preview.Total != 2 || preview.Protocols["hysteria2"] != 1 || preview.Protocols["snell"] != 1 || len(preview.Skipped) != 1 || len(preview.Groups) != 1 {
		t.Fatal(w.Body.String())
	}
	if strings.Contains(w.Body.String(), "unique-secret") || strings.Contains(w.Body.String(), "snell-secret") {
		t.Fatal("preview exposed node credentials")
	}
	snapshot, _ := s.repository.Snapshot(id)
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("preview modified destination")
	}
	w = sourceRequest(s, id, "import-subscription", `{"url":"https://public.test/sub?token=private","conflict":"rename","groups":["Proxy"]}`, token)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var result struct {
		OK                       bool
		Added, Replaced, Skipped int
		Names                    []string
	}
	json.Unmarshal(w.Body.Bytes(), &result)
	if !result.OK || result.Added != 2 || result.Skipped != 1 || len(result.Names) != 2 || calls.Load() != 2 {
		t.Fatal(w.Body.String())
	}
	next := reopen(t, s)
	snapshot, _ = next.repository.Snapshot(id)
	if len(snapshot["nodes"].([]any)) != 2 {
		t.Fatal("restart lost imported nodes")
	}
	original, _ := next.repository.Snapshot("clash")
	if len(original["nodes"].([]any)) != 0 {
		t.Fatal("X-Profile import crossed subscriptions")
	}
	node := snapshot["nodes"].([]any)[0].(map[string]any)["config"].(map[string]any)
	if node["password"] != "unique-secret" || node["sni"] != "hy.example.com" {
		t.Fatal("HY2 credentials/transport lost")
	}
}

func TestSourceRoutesRequireAuthOriginAndHTTPS(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	var calls atomic.Int32
	s.fetchSubscription = func(context.Context, string) (string, error) { calls.Add(1); return sourceFixtureText, nil }
	for _, path := range []string{"/admin/api/import-subscription", "/admin/api/import-subscription/preview"} {
		for _, tc := range []struct {
			token, origin string
			secure        bool
			status        int
		}{{"", "https://panel.test", true, 401}, {token, "https://evil.test", true, 403}, {token, "https://panel.test", false, 426}} {
			w := request(s, "POST", path, `{"url":"https://public.test/sub"}`, tc.token, tc.origin, tc.secure)
			if w.Code != tc.status {
				t.Fatal(w.Code, w.Body.String())
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("unauthorized request reached network")
	}
	if w := sourceRequest(s, "missing-profile", "import-subscription", `{"url":"https://public.test/sub"}`, token); w.Code != 400 || calls.Load() != 0 {
		t.Fatal("invalid destination reached network")
	}
}

func TestSlowSourceDoesNotHoldRepositoryLockAndChecksFreshGroups(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	entered, release := make(chan struct{}), make(chan struct{})
	s.fetchSubscription = func(context.Context, string) (string, error) {
		close(entered)
		<-release
		return sourceFixtureText, nil
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- sourceRequest(s, "clash", "import-subscription", `{"url":"https://public.test/sub","groups":["Deleted"]}`, token)
	}()
	<-entered
	updated := make(chan error, 1)
	go func() {
		updated <- s.repository.Mutate("clash", func(d config.Document) error {
			d["proxy-groups"] = []any{config.Document{"name": "Current", "type": "select", "proxies": []any{"DIRECT"}}}
			return nil
		})
	}()
	select {
	case err := <-updated:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		close(release)
		t.Fatal("network read held repository lock")
	}
	close(release)
	w := <-done
	if w.Code != 400 || !strings.Contains(w.Body.String(), "策略组已变化") {
		t.Fatal("stale groups accepted", w.Code, w.Body.String())
	}
	snapshot, _ := s.repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("failed import partially committed")
	}
}

func TestSourceSlotReleaseFailureAndCancellation(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for i := 0; i < cap(s.sourceSlots); i++ {
		s.sourceSlots <- struct{}{}
	}
	w := sourceRequest(s, "clash", "import-subscription/preview", `{"url":"https://public.test/sub"}`, token)
	if w.Code != 429 {
		t.Fatal(w.Code)
	}
	for i := 0; i < cap(s.sourceSlots); i++ {
		<-s.sourceSlots
	}
	s.fetchSubscription = func(context.Context, string) (string, error) { return "", errors.New("fixture transport failure") }
	w = sourceRequest(s, "clash", "import-subscription", `{"url":"https://public.test/sub"}`, token)
	if w.Code != 400 || len(s.sourceSlots) != 0 {
		t.Fatal("failed fetch leaked concurrency slot")
	}
	s.fetchSubscription = func(context.Context, string) (string, error) { return "not a subscription", nil }
	w = sourceRequest(s, "clash", "import-subscription", `{"url":"https://public.test/sub"}`, token)
	if w.Code != 400 || len(s.sourceSlots) != 0 {
		t.Fatal("parse failure leaked slot")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	s.fetchSubscription = func(context.Context, string) (string, error) { return sourceFixtureText, nil }
	r := httptest.NewRequest("POST", "https://panel.test/admin/api/import-subscription", strings.NewReader(`{"url":"https://public.test/sub"}`)).WithContext(ctx)
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://panel.test")
	r.Header.Set("Authorization", "Bearer "+token)
	w = httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 408 || len(s.sourceSlots) != 0 {
		t.Fatal("canceled import succeeded", w.Code)
	}
	snapshot, _ := s.repository.Snapshot("clash")
	if len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("canceled import modified disk")
	}
}
