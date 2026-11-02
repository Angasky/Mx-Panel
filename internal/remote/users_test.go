package remote

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
)

func TestPythonOwnershipHashesRemainCompatible(t *testing.T) {
	data, err := os.ReadFile("testdata/python-identities.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Row, User              Record
		EndpointHash, UserHash string
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err = decoder.Decode(&rows); err != nil {
		t.Fatal(err)
	}
	for _, sample := range rows {
		hash, err := EndpointIdentity(sample.Row)
		if err != nil || hash != sample.EndpointHash {
			t.Fatal("Python endpoint identity mismatch", err)
		}
		hash, err = UserIdentity(sample.User)
		if err != nil || hash != sample.UserHash {
			t.Fatal("Python user identity mismatch", err)
		}
	}
}
func bindingFor(t *testing.T, row, user Record) Record {
	t.Helper()
	endpoint, err := EndpointIdentity(row)
	if err != nil {
		t.Fatal(err)
	}
	hash, err := UserIdentity(user)
	if err != nil {
		t.Fatal(err)
	}
	return Record{"identityHash": endpoint, "userHash": hash, "userEmail": user["email"]}
}
func TestUserIdentityRejectsReusedInboundAndSharedCredentials(t *testing.T) {
	row := Record{"id": 1, "port": 24443, "protocol": "hysteria", "settings": Record{"version": 2, "clients": []any{}}}
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	row["settings"].(Record)["clients"] = []any{user}
	binding := bindingFor(t, row, user)
	if _, err = FindUser(row, binding, false); err != nil {
		t.Fatal(err)
	}
	row["port"] = 24444
	if _, err = FindUser(row, binding, false); err == nil {
		t.Fatal("reused inbound accepted")
	}
	row["port"] = 24443
	other := Record{"auth": user["auth"], "email": "other"}
	row["settings"].(Record)["clients"] = []any{user, other}
	if _, err = FindUser(row, binding, false); err == nil {
		t.Fatal("shared credential accepted")
	}
	row["settings"].(Record)["clients"] = []any{user}
	user["auth"] = "changed"
	if _, err = FindUser(row, binding, false); err == nil {
		t.Fatal("changed user credential accepted")
	}
}
func TestPanelUserWriteTargetsOnlyOneUser(t *testing.T) {
	row := Record{"id": 1, "port": 24443, "protocol": "hysteria", "settings": Record{"version": 2, "clients": []any{Record{"email": "other", "auth": "other-secret"}}}}
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFor(t, row, user)
	calls := 0
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Error("missing API auth")
		}
		r.ParseForm()
		var settings Record
		json.Unmarshal([]byte(r.Form.Get("settings")), &settings)
		if strings.HasSuffix(r.URL.Path, "addClient") {
			clients := settings["clients"].([]any)
			if len(clients) != 1 || clients[0].(map[string]any)["email"] != user["email"] {
				t.Error("write included another user's settings")
			}
		}
		json.NewEncoder(w).Encode(Record{"success": true})
	}))
	defer host.Close()
	base, _ := url.Parse(host.URL)
	panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
	if _, err = ChangeUser(context.Background(), panel, row, binding, "add", user); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatal("unexpected mutation count")
	}
	row["settings"].(Record)["clients"] = append(row["settings"].(Record)["clients"].([]any), user)
	if _, err = ChangeUser(context.Background(), panel, row, binding, "add", user); err != nil || calls != 1 {
		t.Fatal("idempotent add replayed")
	}
	if _, err = ChangeUser(context.Background(), panel, row, binding, "pause", nil); err != nil {
		t.Fatal(err)
	}
	user["auth"] = "reused"
	before := calls
	if _, err = ChangeUser(context.Background(), panel, row, binding, "remove", nil); err == nil || calls != before {
		t.Fatal("unsafe removal reached remote API")
	}
}
func TestAmbiguousUserWriteIsNotAutomaticallyRetried(t *testing.T) {
	row := Record{"id": 1, "port": 24443, "protocol": "trojan", "settings": Record{"clients": []any{}}}
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFor(t, row, user)
	calls := 0
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		io.Copy(io.Discard, r.Body)
		conn, _, _ := w.(http.Hijacker).Hijack()
		conn.Close()
	}))
	defer host.Close()
	base, _ := url.Parse(host.URL)
	panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
	if _, err = ChangeUser(context.Background(), panel, row, binding, "add", user); err == nil || calls != 1 {
		t.Fatal("ambiguous mutation replayed or reported success")
	}
}

func TestSpecialCredentialPathEncodedExactlyOnce(t *testing.T) {
	user := Record{"email": "owned", "password": "a/b+c: 密码", "enable": true}
	row := Record{"id": 1, "port": 24443, "protocol": "trojan", "settings": Record{"clients": []any{user}}}
	binding := bindingFor(t, row, user)
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := "/base/panel/api/inbounds/1/delClient/a%2Fb%2Bc%3A%20%E5%AF%86%E7%A0%81"
		if r.URL.EscapedPath() != expected {
			t.Errorf("credential path encoding differs: %s", r.URL.EscapedPath())
		}
		json.NewEncoder(w).Encode(Record{"success": true})
	}))
	defer host.Close()
	base, _ := url.Parse(host.URL + "/base/")
	panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
	if _, err := ChangeUser(context.Background(), panel, row, binding, "remove", nil); err != nil {
		t.Fatal(err)
	}
}
func TestMissingOrInvalidCountersNeverBecomeSuccessfulZero(t *testing.T) {
	user := Record{"email": "owned", "password": "secret", "enable": true}
	row := Record{"id": 1, "port": 24443, "protocol": "trojan", "settings": Record{"clients": []any{user}}}
	binding := bindingFor(t, row, user)
	if _, err := UserCounters(row, binding); err == nil {
		t.Fatal("missing stats fabricated as zero")
	}
	row["clientStats"] = []any{Record{"email": "owned", "up": json.Number("9007199254740993"), "down": json.Number("0")}}
	reading, err := UserCounters(row, binding)
	if err != nil || reading["up"] != int64(9007199254740993) {
		t.Fatal("large counter lost precision")
	}
	row["clientStats"] = []any{Record{"email": "owned", "up": json.Number("-1"), "down": json.Number("0")}}
	if _, err = UserCounters(row, binding); err == nil {
		t.Fatal("negative stats accepted")
	}
	if err = CheckEmailNamespace([]Record{row, row}, "owned"); err == nil {
		t.Fatal("duplicate cross-inbound email accepted")
	}
	if err = CheckEmailTarget([]Record{row}, "2", "owned"); err == nil {
		t.Fatal("preexisting email in another inbound accepted before user creation")
	}
}

func TestModernPanelClientJSONFallbackAndScopedRemoval(t *testing.T) {
	row := Record{"id": 1, "port": 443, "protocol": "hysteria", "settings": Record{"version": 2, "clients": []any{}}}
	user, err := NewUser(row)
	if err != nil {
		t.Fatal(err)
	}
	binding := bindingFor(t, row, user)
	var paths []string
	shared := false
	host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.Contains(r.URL.Path, "/inbounds/") {
			w.WriteHeader(404)
			return
		}
		if strings.Contains(r.URL.Path, "/clients/get/") {
			ids := []int{1}
			if shared {
				ids = append(ids, 2)
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": Record{"inboundIds": ids}})
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Error("modern API requires JSON")
		}
		var payload Record
		if json.NewDecoder(r.Body).Decode(&payload) != nil {
			t.Error("invalid JSON")
		}
		if strings.HasSuffix(r.URL.Path, "/add") {
			client := payload["client"].(map[string]any)
			if client["auth"] != user["auth"] || client["email"] != user["email"] || len(payload["inboundIds"].([]any)) != 1 {
				t.Error("HY2 credential or ownership changed")
			}
		} else if strings.HasSuffix(r.URL.Path, "/detach") {
			if len(payload) != 1 || payload["inboundIds"].([]any)[0] != float64(1) {
				t.Error("unscoped deletion")
			}
		} else if strings.Contains(r.URL.Path, "/update/") {
			if payload["enable"] != false {
				t.Error("pause ignored")
			}
		}
		json.NewEncoder(w).Encode(Record{"success": true})
	}))
	defer host.Close()
	base, _ := url.Parse(host.URL)
	panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
	if _, err = ChangeUser(context.Background(), panel, row, binding, "add", user); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || paths[1] != "/panel/api/clients/add" {
		t.Fatal(paths)
	}
	row["settings"].(Record)["clients"] = []any{user}
	if _, err = ChangeUser(context.Background(), panel, row, binding, "pause", nil); err != nil {
		t.Fatal(err)
	}
	shared = true
	before := len(paths)
	if _, err = ChangeUser(context.Background(), panel, row, binding, "pause", nil); err == nil || len(paths) != before+2 {
		t.Fatal("shared global user was mutated")
	}
	if _, err = ChangeUser(context.Background(), panel, row, binding, "remove", nil); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(paths[len(paths)-1], "/detach") {
		t.Fatal("global deletion used")
	}
}

func TestPanelFallbackRequiresExplicit404(t *testing.T) {
	for _, status := range []int{400, 401, 403, 500} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			calls := 0
			host := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; w.WriteHeader(status) }))
			defer host.Close()
			base, _ := url.Parse(host.URL)
			panel := newPanel(base, host.Client().Transport, Record{}, "", "fixture-token", nil)
			row := Record{"id": 1, "protocol": "trojan", "settings": Record{"clients": []any{}}}
			user, _ := NewUser(row)
			binding := bindingFor(t, row, user)
			if _, err := ChangeUser(context.Background(), panel, row, binding, "add", user); err == nil || calls != 1 {
				t.Fatal("mutation replayed after rejection", calls, err)
			}
		})
	}
}
