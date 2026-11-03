package web

import (
	"context"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/remote"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

type webInboundBackend struct {
	*subscriptionBackend
	writes int
}

func (b *webInboundBackend) UpdateInbound(ctx context.Context, server string, id int, payload remote.Record, expected string, guard func(remote.Record, remote.Record) error) (remote.Record, error) {
	old := copyRecord(b.row)
	next := copyRecord(old)
	for k, v := range payload {
		next[k] = v
	}
	if err := guard(old, next); err != nil {
		return nil, err
	}
	b.writes++
	b.row = next
	return remote.Record{"updated": true}, nil
}
func (b *webInboundBackend) DeleteInbound(ctx context.Context, server string, id int, expected string, guard func(remote.Record) error) (remote.Record, error) {
	if err := guard(b.row); err != nil {
		return nil, err
	}
	b.writes++
	return remote.Record{"deleted": true}, nil
}
func TestInboundHTTPRequiresAuthenticationOriginAndIdentity(t *testing.T) {
	s := fixture(t)
	backend := &webInboundBackend{subscriptionBackend: &subscriptionBackend{row: remote.Record{"id": 1, "port": 24001, "protocol": "vless", "enable": true, "settings": remote.Record{"clients": []any{}}, "streamSettings": remote.Record{}}}}
	c := subscriptions.New(s.repository, backend)
	subscriptionControllers.Store(s.repository, c)
	defer subscriptionControllers.Delete(s.repository)
	token := login(t, s)
	body := `{"serverId":"s","inboundId":1,"expectedIdentity":"` + strings.Repeat("a", 64) + `","inbound":{"enable":false}}`
	for _, method := range []string{"PUT", "DELETE"} {
		w := request(s, method, "/admin/api/servers/inbounds", body, "", "https://panel.test", true)
		if w.Code == 200 {
			t.Fatal("unauthenticated write")
		}
		w = request(s, method, "/admin/api/servers/inbounds", body, token, "https://other.test", true)
		if w.Code == 200 {
			t.Fatal("foreign origin write")
		}
		w = request(s, method, "/admin/api/servers/inbounds", `{"serverId":"s","inboundId":1}`, token, "https://panel.test", true)
		if w.Code != 400 {
			t.Fatal(w.Code, w.Body.String())
		}
		w = request(s, method, "/admin/api/servers/inbounds", body, token, "https://panel.test", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if backend.writes != 2 {
		t.Fatal("invalid request reached writer", backend.writes)
	}
}
