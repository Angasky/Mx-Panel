package web

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

type creationHTTPBackend struct {
	*subscriptionBackend
	creates int
}

func (b *creationHTTPBackend) CreateInbound(ctx context.Context, server, profile string, payload remote.Record) (remote.Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.creates++
	return remote.Record{"inbound": copyRecord(b.row)}, nil
}
func TestTemplateCreationHTTPAuthenticationAndImportContract(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	sealer, err := remote.Open(s.options.Root)
	if err != nil {
		t.Fatal(err)
	}
	backend := &creationHTTPBackend{subscriptionBackend: &subscriptionBackend{sealer: sealer, row: remote.Record{"id": 1, "port": 24001, "protocol": "vmess", "enable": true, "remark": "created VMess", "settings": remote.Record{"clients": []any{}}, "streamSettings": remote.Record{"network": "tcp", "security": "none"}}}}
	controller := subscriptions.New(s.repository, backend)
	subscriptionControllers.Store(s.repository, controller)
	defer subscriptionControllers.Delete(s.repository)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := controller.WaitStopped(shutdown); err != nil {
			t.Error(err)
		}
	}()
	if err = controller.Start(ctx); err != nil {
		t.Fatal(err)
	}
	body := `{"serverId":"s","template":"vmess-tcp","operationId":"` + strings.Repeat("a", 32) + `"}`
	for _, route := range []string{"/admin/api/servers/users", "/admin/api/servers/inbounds"} {
		if w := request(s, "POST", route, body, "", "https://panel.test", true); w.Code != 401 {
			t.Fatal("unauthenticated create", w.Code)
		}
		if w := request(s, "POST", route, body, token, "https://other.test", true); w.Code != 403 {
			t.Fatal("foreign origin create", w.Code)
		}
		if w := request(s, "POST", route, body, token, "https://panel.test", true); w.Code != 200 || !strings.Contains(w.Body.String(), `"bound":true`) || !strings.Contains(w.Body.String(), `"shareLinks":["vmess://`) {
			t.Fatal(w.Code, w.Body.String())
		}
		if w := request(s, "GET", "/admin/api/account", "", token, "https://panel.test", true); w.Header().Get("X-Mxioc-Create-Idempotency") != "1" {
			t.Fatal("native creation capability not advertised")
		}
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 1 || backend.adds != 1 {
		t.Fatal("not imported exactly once", err, backend.adds)
	}
	if backend.creates != 2 {
		t.Fatal("invalid request reached creator")
	}
}

func TestRawPanelCreationHTTPDoesNotClaimCredentials(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	sealer, err := remote.Open(s.options.Root)
	if err != nil {
		t.Fatal(err)
	}
	backend := &creationHTTPBackend{subscriptionBackend: &subscriptionBackend{sealer: sealer, row: remote.Record{"id": 1, "port": 24001, "protocol": "vmess", "enable": true, "settings": remote.Record{"clients": []any{remote.Record{"id": "11111111-1111-4111-8111-111111111111", "email": "manual"}}}, "streamSettings": remote.Record{"network": "tcp", "security": "none"}}}}
	controller := subscriptions.New(s.repository, backend)
	subscriptionControllers.Store(s.repository, controller)
	defer subscriptionControllers.Delete(s.repository)
	// No background subscription enforcement is needed for an admin-only create.
	body := `{"serverId":"s","operationId":"` + strings.Repeat("b", 32) + `","inbound":{"port":24001,"protocol":"vmess","settings":{"clients":[{"id":"11111111-1111-4111-8111-111111111111","email":"manual"}]}}}`
	for _, test := range []struct {
		token, origin string
		status        int
	}{{"", "https://panel.test", 401}, {token, "https://other.test", 403}, {token, "https://panel.test", 200}} {
		w := request(s, "POST", "/admin/api/servers/inbounds", body, test.token, test.origin, true)
		if w.Code != test.status {
			t.Fatal(w.Code, w.Body.String())
		}
		if w.Code == 200 && (!strings.Contains(w.Body.String(), `"bound":false`) || !strings.Contains(w.Body.String(), `"enforcementEnabled":false`) || !strings.Contains(w.Body.String(), `"shareLinks":["vmess://`)) {
			t.Fatal(w.Body.String())
		}
	}
	if w := request(s, "POST", "/admin/api/servers/users", body, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("raw operation accepted by subscription-user endpoint", w.Code)
	}
	if backend.creates != 1 || backend.adds != 0 {
		t.Fatal("unexpected side effect", backend.creates, backend.adds)
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("auto imported raw inbound", err)
	}
}

func TestPanelShadowsocksCreationHTTPContract(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	sealer, err := remote.Open(s.options.Root)
	if err != nil {
		t.Fatal(err)
	}
	backend := &creationHTTPBackend{subscriptionBackend: &subscriptionBackend{sealer: sealer, row: remote.Record{"id": 1, "port": 24001, "protocol": "shadowsocks", "enable": true, "settings": remote.Record{"method": "aes-128-gcm", "password": "fixture-secret", "network": "tcp,udp"}, "streamSettings": remote.Record{"network": "tcp", "security": "none"}}}}
	controller := subscriptions.New(s.repository, backend)
	subscriptionControllers.Store(s.repository, controller)
	defer subscriptionControllers.Delete(s.repository)
	body := `{"serverId":"s","operationId":"` + strings.Repeat("c", 32) + `","template":"shadowsocks","port":24001}`
	for _, test := range []struct {
		token, origin string
		status        int
	}{{"", "https://panel.test", 401}, {token, "https://other.test", 403}, {token, "https://panel.test", 200}} {
		w := request(s, "POST", "/admin/api/servers/inbounds", body, test.token, test.origin, true)
		if w.Code != test.status {
			t.Fatal(w.Code, w.Body.String())
		}
		if w.Code == 200 && (!strings.Contains(w.Body.String(), `"bound":false`) || !strings.Contains(w.Body.String(), `"enforcementEnabled":false`) || !strings.Contains(w.Body.String(), `"shareLinks":["ss://`)) {
			t.Fatal(w.Body.String())
		}
	}
	for _, bad := range []string{strings.Replace(body, `24001`, `65536`, 1), strings.Replace(body, `"port":24001`, `"inbound":{},"port":24001`, 1)} {
		if w := request(s, "POST", "/admin/api/servers/inbounds", bad, token, "https://panel.test", true); w.Code != 400 {
			t.Fatal("invalid template reached creator", w.Code)
		}
	}
	if w := request(s, "POST", "/admin/api/servers/users", body, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("single password accepted as subscription user", w.Code)
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 0 || backend.creates != 1 || backend.adds != 0 {
		t.Fatal("single-password template changed subscription", err)
	}
}
