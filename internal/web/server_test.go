package web

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

func fixture(t *testing.T) *Server {
	t.Helper()
	root := t.TempDir()
	salt, hash, err := legacycrypto.NewPassword("long-test-password")
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := json.Marshal(account{Username: "admin", Salt: salt, Hash: hash, Iterations: 600000})
	file := filepath.Join(root, "auth.json")
	if err = os.WriteFile(file, auth, 0600); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, "index.html"), []byte("<h1>fixture</h1>"), 0600)
	profiles, _ := json.Marshal(map[string]any{"profiles": []any{map[string]any{"id": "clash", "name": "fixture", "slug": strings.Repeat("a", 50), "files": []string{filepath.Join(root, "fixture.yaml")}}}})
	os.WriteFile(filepath.Join(root, "profiles.json"), profiles, 0600)
	os.WriteFile(filepath.Join(root, "fixture.yaml"), []byte("proxies: []\nproxy-groups: []\nrules: []\n"), 0600)
	s, err := New(Options{Root: root, AuthFile: file})
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func request(s *Server, method, path, body, token, origin string, secure bool) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://panel.test"+path, bytes.NewBufferString(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.RemoteAddr = "127.0.0.1:2222"
	if secure {
		r.TLS = &tls.ConnectionState{}
	} else {
		r.TLS = nil
	}
	if token != "" {
		r.Header.Set("Authorization", "Bearer "+token)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	return w
}
func login(t *testing.T, s *Server) string {
	t.Helper()
	w := request(s, "POST", "/admin/api/login", `{"username":"admin","password":"long-test-password"}`, "", "https://panel.test", true)
	if w.Code != 200 {
		t.Fatalf("login status %d: %s", w.Code, w.Body.String())
	}
	var value struct{ Token string }
	json.Unmarshal(w.Body.Bytes(), &value)
	if value.Token == "" {
		t.Fatal("missing token")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatal("unsafe session cookie")
	}
	return value.Token
}
func TestSessionLifecycleAndReadContracts(t *testing.T) {
	s := fixture(t)
	if w := request(s, "GET", "/admin/api/profiles", "", "", "", true); w.Code != 401 {
		t.Fatal("unauthenticated access")
	}
	token := login(t, s)
	for _, path := range []string{"/admin/api/account", "/admin/api/profiles", "/admin/api/snapshot", "/admin/api/raw"} {
		w := request(s, "GET", path, "", token, "", true)
		if w.Code != 200 {
			t.Fatal(path, w.Code, w.Body.String())
		}
		if strings.Contains(w.Body.String(), `"files":`) || strings.Contains(w.Body.String(), s.account.Hash) {
			t.Fatal("private credential or path leaked")
		}
	}
	r := httptest.NewRequest("GET", "https://panel.test/admin/api/account", nil)
	r.TLS = &tls.ConnectionState{}
	r.AddCookie(&http.Cookie{Name: "mxioc_session", Value: token})
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatal("cookie authentication failed")
	}
	if request(s, "POST", "/admin/api/logout", "{}", token, "https://panel.test", true).Code != 200 {
		t.Fatal("logout failed")
	}
	if request(s, "GET", "/admin/api/account", "", token, "", true).Code != 401 {
		t.Fatal("logout did not revoke session")
	}
	token = login(t, s)
	s.now = func() time.Time { return time.Now().Add(13 * time.Hour) }
	if request(s, "GET", "/admin/api/account", "", token, "", true).Code != 401 {
		t.Fatal("expired session accepted")
	}
}
func TestTransportOriginAndLoginLimits(t *testing.T) {
	s := fixture(t)
	if request(s, "POST", "/admin/api/login", "{}", "", "https://panel.test", false).Code != 426 {
		t.Fatal("cleartext login accepted")
	}
	for _, origin := range []string{"", "null", "https://evil.test", "http://panel.test", "https://panel.test/path"} {
		if request(s, "POST", "/admin/api/login", "{}", "", origin, true).Code != 403 {
			t.Fatal("invalid origin accepted", origin)
		}
	}
	for i := 0; i < 5; i++ {
		if request(s, "POST", "/admin/api/login", `{"username":"admin","password":"bad"}`, "", "https://panel.test", true).Code != 403 {
			t.Fatal("unexpected login failure status")
		}
	}
	if request(s, "POST", "/admin/api/login", `{"username":"admin","password":"long-test-password"}`, "", "https://panel.test", true).Code != 429 {
		t.Fatal("brute force lock missing")
	}
	s.now = func() time.Time { return time.Now().Add(16 * time.Minute) }
	login(t, s)
}
func TestMalformedBodyAndFailClosedStartup(t *testing.T) {
	s := fixture(t)
	for _, body := range []string{`{} {}`, `[]`, `{`, strings.Repeat("x", (2<<20)+1)} {
		if request(s, "POST", "/admin/api/login", body, "", "https://panel.test", true).Code != 400 {
			t.Fatal("invalid body accepted")
		}
	}
	if _, err := New(Options{AuthFile: filepath.Join(t.TempDir(), "missing")}); err == nil {
		t.Fatal("missing auth permitted")
	}
}

func TestNodeHTTPWorkflowAndRejectedWrites(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	for _, name := range []string{"A", "B"} {
		body := `{"config":{"name":"` + name + `","type":"hysteria2","server":"vpn.example.com","port":24443,"password":"secret"}}`
		w := request(s, "POST", "/admin/api/nodes", body, token, "https://panel.test", true)
		if w.Code != 200 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	w := request(s, "POST", "/admin/api/nodes/move", `{"name":"B","targetName":"A","position":"before"}`, token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(s, "GET", "/admin/api/snapshot", "", token, "", true)
	var snapshot struct{ Nodes []struct{ Name string } }
	json.Unmarshal(w.Body.Bytes(), &snapshot)
	if len(snapshot.Nodes) != 2 || snapshot.Nodes[0].Name != "B" {
		t.Fatal("HTTP order not saved")
	}
	var wire map[string]any
	json.Unmarshal(w.Body.Bytes(), &wire)
	for _, value := range wire["nodes"].([]any) {
		if _, ok := value.(map[string]any)["port"].(float64); !ok {
			t.Fatal("JSON numeric port was persisted as YAML string")
		}
	}
	w = request(s, "PUT", "/admin/api/nodes", `{"oldName":"B","config":{"name":"C","type":"snell","server":"vpn.example.com","port":24443,"psk":" secret ","version":4}}`, token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	for _, body := range []string{`{"config":{"name":"bad","type":"vless","server":"x","port":-1}}`, `null`, `[]`} {
		w = request(s, "POST", "/admin/api/nodes", body, token, "https://panel.test", true)
		if w.Code != 400 {
			t.Fatal("invalid mutation accepted")
		}
	}
	w = request(s, "DELETE", "/admin/api/nodes", `{"name":"C"}`, token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	w = request(s, "GET", "/admin/api/snapshot", "", token, "", true)
	json.Unmarshal(w.Body.Bytes(), &snapshot)
	if len(snapshot.Nodes) != 1 || snapshot.Nodes[0].Name != "A" {
		t.Fatal("HTTP delete failed")
	}
}

func TestActualHTTPSCookieWorkflow(t *testing.T) {
	handler := fixture(t)
	host := httptest.NewTLSServer(handler)
	defer host.Close()
	client := host.Client()
	jar, _ := cookiejar.New(nil)
	client.Jar = jar
	body := strings.NewReader(`{"username":"admin","password":"long-test-password"}`)
	req, _ := http.NewRequest("POST", host.URL+"/admin/api/login", body)
	req.Header.Set("Origin", host.URL)
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("HTTPS login failed", res.StatusCode)
	}
	res, err = client.Get(host.URL + "/admin/api/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != 200 || !strings.Contains(string(data), `"nodes":[]`) {
		t.Fatal("authenticated HTTPS snapshot failed")
	}
	req, _ = http.NewRequest("POST", host.URL+"/admin/api/logout", strings.NewReader(`{}`))
	req.Header.Set("Origin", host.URL)
	req.Header.Set("Content-Type", "application/json")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("HTTPS logout failed")
	}
	res, err = client.Get(host.URL + "/admin/api/snapshot")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 401 {
		t.Fatal("revoked HTTPS cookie accepted")
	}
}

func TestAccountChangePersistsAndRevokesEverySession(t *testing.T) {
	s := fixture(t)
	first := login(t, s)
	second := login(t, s)
	w := request(s, "POST", "/admin/api/account", `{"username":"admin","current":"wrong","newPassword":"new-password-12345"}`, first, "https://panel.test", true)
	if w.Code != 403 {
		t.Fatal("wrong current password accepted")
	}
	w = request(s, "POST", "/admin/api/account", `{"username":"admin","current":"long-test-password","newUsername":"new-admin","newPassword":"new-password-12345"}`, first, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, token := range []string{first, second} {
		if request(s, "GET", "/admin/api/account", "", token, "", true).Code != 401 {
			t.Fatal("old session survived credential change")
		}
	}
	reopened, err := New(s.options)
	if err != nil {
		t.Fatal(err)
	}
	w = request(reopened, "POST", "/admin/api/login", `{"username":"new-admin","password":"new-password-12345"}`, "", "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal("new credentials did not survive restart", w.Body.String())
	}
}

func TestEditingHTTPRoutes(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	tasks := []struct{ method, path, body string }{
		{"POST", "/admin/api/groups", `{"config":{"name":"Media","type":"select","proxies":["DIRECT"]}}`},
		{"POST", "/admin/api/rules", `{"type":"DOMAIN-SUFFIX","value":"example.com","action":"Media"}`},
		{"POST", "/admin/api/dns", `{"domain":"+.example.com","servers":["1.1.1.1"]}`},
		{"PUT", "/admin/api/groups", `{"oldName":"Media","config":{"name":"Video","type":"select","proxies":["DIRECT"]}}`},
	}
	for _, task := range tasks {
		w := request(s, task.method, task.path, task.body, token, "https://panel.test", true)
		if w.Code != 200 {
			t.Fatal(task.path, w.Code, w.Body.String())
		}
	}
	w := request(s, "GET", "/admin/api/snapshot", "", token, "", true)
	var snap struct {
		Rules       []struct{ Value, Action string }
		DNSPolicies []any
	}
	json.Unmarshal(w.Body.Bytes(), &snap)
	if len(snap.Rules) != 1 || snap.Rules[0].Action != "Video" || snap.Rules[0].Value != "example.com" || len(snap.DNSPolicies) != 1 {
		t.Fatal("edited snapshot contract differs", w.Body.String())
	}
}

func TestBatchLinkImportShareAndQRCode(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	uri := "snell://" + base64.RawStdEncoding.EncodeToString([]byte("chacha20-ietf-poly1305: 密码:@+secret @vpn.example.com:24443")) + "?version=4#Snell"
	payload, _ := json.Marshal(map[string]any{"links": uri + "\n" + uri + "\nbad://secret@host:443"})
	w := request(s, "POST", "/admin/api/import-node", string(payload), token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	var imported struct {
		Total, Added    int
		Failed, Renamed []any
	}
	json.Unmarshal(w.Body.Bytes(), &imported)
	if imported.Total != 3 || imported.Added != 2 || len(imported.Failed) != 1 || len(imported.Renamed) != 1 {
		t.Fatal("batch import result differs", w.Body.String())
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=Snell", "", token, "", true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	var shared struct{ URI string }
	json.Unmarshal(w.Body.Bytes(), &shared)
	encoded := strings.Split(strings.TrimPrefix(shared.URI, "snell://"), "?")[0]
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil || string(raw) != "chacha20-ietf-poly1305: 密码:@+secret @vpn.example.com:24443" {
		t.Fatal("exported Snell auth payload lost PSK")
	}
	w = request(s, "GET", "/admin/api/nodes/qrcode?name=Snell&profile=clash", "", token, "", true)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Type"), "image/svg+xml") || !strings.Contains(w.Body.String(), `fill="#fff"`) {
		t.Fatal("node QR missing white background")
	}
	if request(s, "GET", "/admin/api/nodes/qrcode?name=Snell&profile=missing", "", token, "", true).Code != 400 {
		t.Fatal("QR ignored selected profile")
	}
	if request(s, "GET", "/admin/api/nodes/qrcode?name=Snell", "", "", "", true).Code != 401 {
		t.Fatal("node QR bypassed authentication")
	}
}

func TestNativeServerMetadataRoutesDoNotExposeCredentials(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	pin := "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32))
	payload, _ := json.Marshal(map[string]any{"name": "fixture server", "host": "198.51.100.20", "sshPort": 22, "sshUser": "root", "sshPassword": "sample-server-password", "fingerprint": pin, "installType": "xray", "connectionMode": "existing"})
	w := request(s, "POST", "/admin/api/servers", string(payload), token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "sample-server-password") {
		t.Fatal("server credential exposed")
	}
	var created struct{ Server struct{ ID string } }
	json.Unmarshal(w.Body.Bytes(), &created)
	w = request(s, "GET", "/admin/api/servers", "", token, "", true)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "fixture server") || strings.Contains(w.Body.String(), "sshPassword") {
		t.Fatal("server list contract or redaction failed")
	}
	updated, _ := json.Marshal(map[string]any{"id": created.Server.ID, "name": "renamed"})
	w = request(s, "PUT", "/admin/api/servers", string(updated), token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Body.String())
	}
	if request(s, "GET", "/admin/api/servers", "", "", "", true).Code != 401 {
		t.Fatal("server metadata bypassed authentication")
	}
}
