package web

import (
	"context"
	"strings"
	"testing"

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
	defer cancel()
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
