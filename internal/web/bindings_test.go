package web

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func TestBindingAndServerRemovalHTTP(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	manager, err := s.remoteManager()
	if err != nil {
		t.Fatal(err)
	}
	server, err := manager.Save(remote.Record{"name": "offline", "host": "192.0.2.1", "sshPassword": "test-password", "fingerprint": "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "panelPassword": "test-password"})
	if err != nil {
		t.Fatal(err)
	}
	id := server["id"].(string)
	if err = s.repository.UpdateState("clash", func(p config.Document) error {
		p["traffic"] = config.Document{"upload": 123}
		p["remoteNodes"] = []any{config.Document{"serverId": id, "status": "active", "operationId": "owned", "pendingUser": "private"}, config.Document{"serverId": id, "status": "missing", "operationId": "history"}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"id":%q,"detach":true}`, id)
	if w := request(s, "DELETE", "/admin/api/servers", body, "", "https://panel.test", true); w.Code != 401 {
		t.Fatal("missing authentication", w.Code)
	}
	if w := request(s, "DELETE", "/admin/api/servers", body, token, "https://elsewhere.test", true); w.Code != 403 {
		t.Fatal("wrong origin", w.Code)
	}
	if w := request(s, "DELETE", "/admin/api/servers", fmt.Sprintf(`{"id":%q}`, id), token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("unconfirmed detach", w.Code, w.Body.String())
	}
	if w := request(s, "DELETE", "/admin/api/servers", body, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if _, err = manager.Record(id); err == nil {
		t.Fatal("server was not forgotten")
	}
	p, _ := s.repository.State("clash")
	if p["remoteNodes"].([]any)[0].(map[string]any)["status"] != "detached" {
		t.Fatal("binding not detached")
	}
	var traffic map[string]any
	w := request(s, "GET", "/admin/api/traffic", "", token, "", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &traffic) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	binding := traffic["bindings"].([]any)[0].(map[string]any)
	if _, ok := binding["pendingUser"]; ok {
		t.Fatal("private credential leaked")
	}
	// Snapshot and dedicated traffic endpoints must mint the same profile token.
	var snapshot map[string]any
	w = request(s, "GET", "/admin/api/snapshot", "", token, "", true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &snapshot) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	public, _ := s.repository.Profiles()
	projected := public[0]["traffic"].(map[string]any)["bindings"].([]any)[0].(map[string]any)
	if projected["recordToken"] != binding["recordToken"] {
		t.Fatal("profile and traffic tokens differ")
	}
	invalid := fmt.Sprintf(`{"recordIndex":true,"recordToken":%q,"confirmed":true}`, binding["recordToken"])
	if w = request(s, "PUT", "/admin/api/traffic/bindings/remove", invalid, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("boolean index accepted")
	}
	remove := fmt.Sprintf(`{"recordIndex":0,"recordToken":%q,"confirmed":true}`, binding["recordToken"])
	if w = request(s, "PUT", "/admin/api/traffic/bindings/remove", remove, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "PUT", "/admin/api/traffic/bindings/remove", remove, token, "https://panel.test", true); w.Code != 400 {
		t.Fatal("stale record removed a different row")
	}
	if w = request(s, "PUT", "/admin/api/traffic/bindings/cleanup", `{"confirmed":true}`, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	p, _ = s.repository.State("clash")
	if len(p["remoteNodes"].([]any)) != 0 || fmt.Sprint(p["traffic"].(map[string]any)["upload"]) != "123" {
		t.Fatal("cleanup changed usage or left history")
	}
}
