package config

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPublicCapabilityAndQuotaState(t *testing.T) {
	r, _, _ := fixture(t)
	slug := strings.Repeat("b", 50)
	now := time.Unix(1800000000, 0)
	if err := r.UpdateState("clash", func(p Document) error {
		p["slug"] = slug
		p["traffic"] = Document{"enabled": true, "enforce": true, "upload": int64(12), "download": int64(34), "total": int64(100), "expire": now.Unix() + 100}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	source, err := r.PublicSubscription(slug, now)
	if err != nil {
		t.Fatal(err)
	}
	if source.Userinfo != "upload=12; download=34; total=100; expire=1800000100" || !strings.Contains(string(source.Raw), "9007199254740993") {
		t.Fatal("headers or raw YAML changed", source.Userinfo)
	}
	for _, token := range []string{"clash", "../profiles.json", strings.Repeat("c", 50), slug + "/extra"} {
		if _, err = r.PublicSubscription(token, now); !errors.Is(err, ErrSubscriptionMissing) {
			t.Fatal("invalid capability resolved", token, err)
		}
	}
	if err = r.UpdateState("clash", func(p Document) error { p["traffic"].(Document)["upload"] = int64(66); return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err = r.PublicSubscription(slug, now); !errors.Is(err, ErrSubscriptionBlocked) {
		t.Fatal("quota bypass", err)
	}
	if _, err = r.ConversionSource("clash", now); err != nil {
		t.Fatal("administrator compatibility read blocked", err)
	}
	p, _ := r.State("clash")
	if p["traffic"].(Document)["enforce"] != true {
		t.Fatal("management read disabled enforcement")
	}
	_ = r.UpdateState("clash", func(p Document) error { p["traffic"].(Document)["enforce"] = false; return nil })
	if _, err = r.PublicSubscription(slug, now); err != nil {
		t.Fatal("display-only quota was enforced", err)
	}
	_ = r.UpdateState("clash", func(p Document) error { p["accessRevoked"] = true; return nil })
	if _, err = r.PublicSubscription(slug, now); !errors.Is(err, ErrSubscriptionBlocked) {
		t.Fatal("revoked subscription exported")
	}
}
