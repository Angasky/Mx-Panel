package remote

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestPanelCSRFSessionReuseAndExplicitExpiryRecovery(t *testing.T) {
	var logins atomic.Int32
	var expired atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/base/csrf-token":
			json.NewEncoder(w).Encode(Record{"success": true, "obj": "csrf-fixture"})
		case "/base/login":
			if r.Header.Get("X-CSRF-Token") != "csrf-fixture" {
				w.WriteHeader(403)
				return
			}
			r.ParseForm()
			if r.Form.Get("username") != "admin" || r.Form.Get("password") != "panel-password" {
				json.NewEncoder(w).Encode(Record{"success": false})
				return
			}
			logins.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "panel-session", Value: "fixture", Path: "/base/"})
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/base/panel/api/inbounds/list":
			if expired.CompareAndSwap(true, false) {
				w.WriteHeader(401)
				return
			}
			if _, err := r.Cookie("panel-session"); err != nil {
				w.WriteHeader(401)
				return
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": []Record{{"id": 1, "up": 9007199254740993}}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/base/")
	state := NewPanelSession()
	panel := newPanel(base, server.Client().Transport, Record{"panelUser": "admin", "connectionMode": "existing"}, "panel-password", "", state)
	for i := 0; i < 2; i++ {
		result, err := panel.Request(context.Background(), "panel/api/inbounds/list", nil, "")
		if err != nil {
			t.Fatal(err)
		}
		rows := result.([]any)
		if rows[0].(map[string]any)["up"].(json.Number).String() != "9007199254740993" {
			t.Fatal("traffic integer lost precision")
		}
	}
	if logins.Load() != 1 {
		t.Fatal("background requests rotated panel login")
	}
	expired.Store(true)
	if _, err := panel.Request(context.Background(), "panel/api/inbounds/list", nil, ""); err != nil {
		t.Fatal(err)
	}
	if logins.Load() != 2 {
		t.Fatal("explicit session expiry not recovered")
	}
}
func TestPanelBearerAvoidsBrowserLoginAndMutationsAreNotReplayed(t *testing.T) {
	var logins, mutations atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "login") {
			logins.Add(1)
		}
		if r.Header.Get("Authorization") != "Bearer api-fixture" {
			w.WriteHeader(401)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/add") {
			mutations.Add(1)
			connection, _, _ := w.(http.Hijacker).Hijack()
			connection.Close()
			return
		}
		json.NewEncoder(w).Encode(Record{"success": true, "obj": []any{}})
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/base/")
	panel := newPanel(base, server.Client().Transport, Record{"panelUser": "admin"}, "password", "api-fixture", NewPanelSession())
	if _, err := panel.Request(context.Background(), "panel/api/inbounds/list", nil, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := panel.Request(context.Background(), "panel/api/inbounds/add", Record{"settings": Record{"clients": []any{}}}, ""); err == nil {
		t.Fatal("interrupted mutation reported success")
	}
	if mutations.Load() != 1 || logins.Load() != 0 {
		t.Fatal("mutation replayed or token request triggered a browser login")
	}
}
func TestLegacyXUIFallbackOnlyAfterRead404(t *testing.T) {
	var modern, legacy atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/csrf-token":
			w.WriteHeader(404)
		case "/login":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			json.NewEncoder(w).Encode(Record{"success": true})
		case "/panel/api/inbounds/list":
			modern.Add(1)
			w.WriteHeader(404)
		case "/xui/API/inbounds/list":
			legacy.Add(1)
			json.NewEncoder(w).Encode(Record{"success": true, "obj": []any{}})
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	base, _ := url.Parse(server.URL + "/")
	panel := newPanel(base, server.Client().Transport, Record{"installType": "x-ui", "connectionMode": "existing", "panelUser": "admin"}, "password", "", nil)
	if _, err := panel.Request(context.Background(), "panel/api/inbounds/list", nil, ""); err != nil {
		t.Fatal(err)
	}
	if modern.Load() != 1 || legacy.Load() != 1 {
		t.Fatal("legacy API fallback did not follow explicit read 404")
	}
}
