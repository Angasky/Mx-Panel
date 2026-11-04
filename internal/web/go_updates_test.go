package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestGoUpdateSelectsNewestCompleteRelease(t *testing.T) {
	release := func(v string) string {
		return fmt.Sprintf(`{"tag_name":"go-%[1]s","assets":[{"name":"SHA256SUMS","state":"uploaded","size":10},{"name":"mxioc-go-%[1]s-linux-amd64.tar.gz","state":"uploaded","size":10},{"name":"mxioc-go-%[1]s-linux-arm64.tar.gz","state":"uploaded","size":10}]}`, v)
	}
	var releases []goRelease
	if err := json.Unmarshal([]byte(`[`+release("v1.2.0")+","+release("v1.10.0")+`,{"tag_name":"go-v2.0.0"}]`), &releases); err != nil {
		t.Fatal(err)
	}
	if got := newestGoRelease(releases); got != "v1.10.0" {
		t.Fatalf("latest release: %q", got)
	}
	var u goUpdates
	now := time.Now()
	u.check(context.Background(), now, func(context.Context) (string, error) { return newestGoRelease(releases), nil })
	u.check(context.Background(), now.Add(time.Second), func(context.Context) (string, error) {
		t.Fatal("check should be throttled")
		return "", nil
	})
	u.check(context.Background(), now.Add(time.Minute), func(context.Context) (string, error) { return "", errors.New("offline") })
	if status := u.status("v1.9.0"); !status.Available || status.CheckError == "" {
		t.Fatalf("cached status lost after failure: %+v", status)
	}
	if status := u.status("v2.0.0"); status.Available {
		t.Fatal("older build advertised as update")
	}
}

func TestGoUpdateDismissRequiresOriginAndPersists(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	s.updates.latest = "v1.2.0"
	path := "/admin/api/updates/dismiss"
	body := `{"version":"v1.2.0"}`
	if w := request(s, "POST", path, body, token, "https://foreign.test", true); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", path, `{"version":"v1.1.0"}`, token, "https://panel.test", true); w.Code != 409 {
		t.Fatal(w.Code)
	}
	if w := request(s, "POST", path, body, token, "https://panel.test", true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	reopened, err := New(s.options)
	if err != nil || reopened.updates.ignored != "v1.2.0" {
		t.Fatalf("ignored version did not persist: %v", err)
	}
}
