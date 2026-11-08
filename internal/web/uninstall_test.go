package web

import (
	"context"
	"github.com/Angasky/dingzhi-ban/internal/releaseupdate"
	"strings"
	"testing"
)

type fakeServiceUninstaller struct {
	calls int
	err   error
}

func (f *fakeServiceUninstaller) StartUninstall(context.Context, string) (*releaseupdate.Job, error) {
	f.calls++
	return &releaseupdate.Job{ID: "test", Operation: "uninstall", Status: "queued"}, f.err
}

func TestUninstallRequiresOriginAuthenticationAndPreservesData(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	backend := &fakeServiceUninstaller{}
	s.options.ServiceUninstaller = backend
	good := `{"username":"admin","password":"long-test-password","confirmation":"UNINSTALL","purgeData":false}`
	for _, test := range []struct {
		body, token, origin string
		code                int
	}{
		{good, "", "https://panel.test", 401}, {good, token, "https://other.test", 403},
		{`{"username":"admin","password":"wrong","confirmation":"UNINSTALL"}`, token, "https://panel.test", 403},
		{`{"username":"admin","password":"long-test-password","confirmation":"wrong"}`, token, "https://panel.test", 400},
		{`{"username":"admin","password":"long-test-password","confirmation":"UNINSTALL","purgeData":true}`, token, "https://panel.test", 400},
		{`{"purgeData":"false"}`, token, "https://panel.test", 400},
	} {
		w := request(s, "POST", "/admin/api/uninstall", test.body, test.token, test.origin, true)
		if w.Code != test.code || backend.calls != 0 {
			t.Fatal("removal guard failed", w.Code, w.Body.String())
		}
	}
	w := request(s, "POST", "/admin/api/uninstall", good, token, "https://panel.test", true)
	if w.Code != 202 || backend.calls != 1 {
		t.Fatal(w.Code, w.Body.String())
	}
	backend.err = releaseupdate.ErrBusy
	w = request(s, "POST", "/admin/api/uninstall", good, token, "https://panel.test", true)
	if w.Code != 409 {
		t.Fatal("busy operation not reported")
	}
	s.options.ServiceUninstaller = nil
	if w := request(s, "POST", "/admin/api/uninstall", good, token, "https://panel.test", true); w.Code != 409 {
		t.Fatal("unmanaged install accepted")
	}
	if w := request(s, "GET", "/admin/api/uninstall", "", token, "", true); w.Code != 405 {
		t.Fatal("read triggered uninstall")
	}
	if _, err := s.repository.Snapshot("clash"); err != nil {
		t.Fatal("request modified data", err)
	}
}

type fakePurgeUninstaller struct {
	fakeServiceUninstaller
	purge bool
}

func (f *fakePurgeUninstaller) StartUninstallWithData(_ context.Context, _ string, purge bool) (*releaseupdate.Job, error) {
	f.calls++
	f.purge = purge
	return &releaseupdate.Job{Operation: "uninstall", PurgeData: purge, Status: "queued"}, f.err
}
func TestPurgeUninstallRequiresSeparateConfirmationAndCredentials(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	backend := &fakePurgeUninstaller{}
	s.options.ServiceUninstaller = backend
	good := `{"username":"admin","password":"long-test-password","confirmation":"UNINSTALL","purgeData":true,"purgeConfirmation":"DELETE ALL DATA"}`
	for _, test := range []struct {
		body string
		code int
	}{
		{strings.Replace(good, "DELETE ALL DATA", "wrong", 1), 400},
		{strings.Replace(good, "long-test-password", "wrong", 1), 403},
	} {
		w := request(s, "POST", "/admin/api/uninstall", test.body, token, "https://panel.test", true)
		if w.Code != test.code || backend.calls != 0 {
			t.Fatal("purge guard failed", w.Code)
		}
	}
	w := request(s, "POST", "/admin/api/uninstall", good, token, "https://panel.test", true)
	if w.Code != 202 || backend.calls != 1 || !backend.purge || !strings.Contains(w.Body.String(), `"preservedData":false`) {
		t.Fatal("purge not queued", w.Code, w.Body.String())
	}
	if _, err := s.repository.Snapshot("clash"); err != nil {
		t.Fatal("HTTP handler deleted local data", err)
	}
}
