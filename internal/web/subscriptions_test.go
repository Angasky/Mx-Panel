package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

type subscriptionBackend struct {
	mu     sync.Mutex
	sealer *remote.Manager
	row    remote.Record
	adds   int
}

func (b *subscriptionBackend) Record(id string) (remote.Record, error) {
	return remote.Record{"id": id, "host": "192.0.2.1", "installType": "3x-ui"}, nil
}
func (b *subscriptionBackend) SealUser(user remote.Record) (string, error) {
	return b.sealer.SealUser(user)
}
func (b *subscriptionBackend) OpenUser(token string) (remote.Record, error) {
	return b.sealer.OpenUser(token)
}
func copyRecord(row remote.Record) remote.Record {
	data, _ := json.Marshal(row)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var out remote.Record
	_ = decoder.Decode(&out)
	return out
}
func (b *subscriptionBackend) Inbounds(context.Context, string) (remote.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return remote.Record{"inbounds": []any{copyRecord(b.row)}}, nil
}
func (b *subscriptionBackend) SubscriptionUser(ctx context.Context, id string, binding remote.Record, op string, user remote.Record) (remote.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	current, err := remote.FindUser(b.row, binding, op == "add" || op == "remove")
	if err != nil {
		return nil, err
	}
	settings := b.row["settings"].(map[string]any)
	if current == nil && op == "add" {
		current = copyRecord(user)
		settings["clients"] = append(settings["clients"].([]any), current)
		b.adds++
	}
	if op == "remove" {
		next := []any{}
		for _, v := range settings["clients"].([]any) {
			if v.(map[string]any)["email"] != binding["userEmail"] {
				next = append(next, v)
			}
		}
		settings["clients"] = next
		return remote.Record{"removed": true}, nil
	}
	if current == nil {
		return nil, errors.New("missing")
	}
	if op == "pause" || op == "resume" {
		current["enable"] = op == "resume"
	}
	return remote.Record{"inbound": copyRecord(b.row), "client": copyRecord(current), "reading": remote.Record{"up": int64(0), "down": int64(0), "source": "authenticated-client"}}, nil
}
func TestSubscriptionHTTPProfileIsolationAuthenticationAndDurability(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	sealer, err := remote.Open(s.options.Root)
	if err != nil {
		t.Fatal(err)
	}
	b := &subscriptionBackend{sealer: sealer, row: remote.Record{"id": 1, "port": 24443, "protocol": "hysteria", "enable": true, "remark": "HY2", "settings": remote.Record{"version": 2, "clients": []any{}}, "streamSettings": remote.Record{}}}
	c := subscriptions.New(s.repository, b)
	subscriptionControllers.Store(s.repository, c)
	t.Cleanup(func() { subscriptionControllers.Delete(s.repository) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err = c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body, profile, auth, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://panel.test/admin/api/"+path, strings.NewReader(body))
		r.TLS = &tls.ConnectionState{}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Profile", profile)
		r.Header.Set("Origin", origin)
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	body := `{"serverId":"s","inboundIds":[1]}`
	if w := call("POST", "servers/users/batch", body, "clash", "", "https://panel.test"); w.Code != 401 {
		t.Fatal("unauthenticated batch allowed")
	}
	if w := call("POST", "servers/users/batch", body, "clash", token, "https://other.test"); w.Code != 403 {
		t.Fatal("cross-origin batch allowed")
	}
	w := call("POST", "servers/users/batch", body, "clash", token, "https://panel.test")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"succeeded":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	second, err := s.repository.CreateProfile(map[string]any{"name": "second", "templateId": "blank"})
	if err != nil {
		t.Fatal(err)
	}
	other := second["id"].(string)
	w = call("POST", "servers/users/batch", body, other, token, "https://panel.test")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"succeeded":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, profile := range []string{"clash", other} {
		w = call("GET", "snapshot", "", profile, token, "")
		var snapshot map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &snapshot)
		if w.Code != 200 || len(snapshot["nodes"].([]any)) != 1 {
			t.Fatal("import not in selected profile snapshot", w.Body.String())
		}
		info := snapshot["profile"].(map[string]any)["traffic"].(map[string]any)
		if info["configured"] != true || len(info["bindings"].([]any)) != 1 {
			t.Fatal("snapshot profile traffic differs from traffic endpoint")
		}
		w = call("GET", "traffic", "", profile, token, "")
		if w.Code != 200 || strings.Contains(w.Body.String(), "pendingUser") || strings.Contains(w.Body.String(), "userHash") {
			t.Fatal("private ownership exposed", w.Body.String())
		}
	}
	for _, bad := range []string{`{"serverId":"s","inboundIds":[true]}`, `{"serverId":"s","inboundIds":["1"]}`, `{"serverId":"s","inboundIds":[1,1]}`, `{"serverId":"s","inboundIds":[]}`} {
		if w := call("POST", "servers/users/batch", bad, "clash", token, "https://panel.test"); w.Code != 400 {
			t.Fatal("invalid IDs accepted", w.Code, w.Body.String())
		}
	}
	if b.adds != 2 {
		t.Fatal("invalid requests or profile reuse duplicated remote grants")
	}
	if err = s.repository.UpdateState("clash", func(p map[string]any) error {
		p["traffic"].(map[string]any)["expire"] = time.Now().Add(-time.Hour).Unix()
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	w = call("POST", "traffic/sync", "{}", "clash", token, "https://panel.test")
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	b.mu.Lock()
	clients := b.row["settings"].(map[string]any)["clients"].([]any)
	count := len(clients)
	b.mu.Unlock()
	if count != 1 {
		t.Fatal("expiry removed peer profile's user")
	}
	if w := call("POST", "servers/users/batch", body, "clash", token, "https://panel.test"); w.Code != 400 {
		t.Fatal("expired subscription granted another credential")
	}
}
