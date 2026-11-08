package geo

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestPublicIPLookupCacheAndProviderContract(t *testing.T) {
	r := New()
	r.interval = 0
	calls := 0
	r.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8")}, nil
	}
	r.fetch = func(ctx context.Context, url string) (string, error) {
		calls++
		if url != "https://api.country.is/8.8.8.8" {
			t.Fatal(url)
		}
		return `{"country":"us"}`, nil
	}
	for i := 0; i < 2; i++ {
		country, err := r.Lookup(context.Background(), "node.example.com")
		if err != nil || country.Code != "US" || country.IP != "8.8.8.8" {
			t.Fatal(country, err)
		}
	}
	if calls != 1 {
		t.Fatal("cache not reused")
	}
	r.cache["8.8.8.8"] = cached{Country{"US", "8.8.8.8"}, time.Now().Add(-8 * 24 * time.Hour)}
	if _, err := r.Lookup(context.Background(), "8.8.8.8"); err != nil || calls != 2 {
		t.Fatal("expired cache used", err)
	}
}
func TestPrivateDNSBadResponsesAndCancellation(t *testing.T) {
	r := New()
	r.interval = 0
	r.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")}, nil
	}
	r.fetch = func(context.Context, string) (string, error) {
		t.Fatal("nonpublic node sent to provider")
		return "", nil
	}
	for _, host := range []string{"127.0.0.1", "10.0.0.1"} {
		if _, err := r.Lookup(context.Background(), host); err == nil {
			t.Fatal("private target accepted")
		}
	}
	for _, body := range []string{`{}`, `{"country":"USA"}`, `{"country":"12"}`, strings.Repeat("x", 65537)} {
		r.fetch = func(context.Context, string) (string, error) { return body, nil }
		if _, err := r.Lookup(context.Background(), "1.1.1.1"); err == nil {
			t.Fatal("invalid geo accepted")
		}
	}
	r.next = time.Now().Add(time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := r.Lookup(ctx, "1.1.1.1"); err == nil {
		t.Fatal("cancellation ignored")
	}
}

func TestMixedDNSUsesFirstPublicAddressLikePython(t *testing.T) {
	for _, answers := range [][]netip.Addr{
		{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")},
		{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("127.0.0.1")},
		{netip.MustParseAddr("::1"), netip.MustParseAddr("::ffff:8.8.8.8")},
	} {
		r := New()
		r.interval = 0
		r.lookup = func(context.Context, string, string) ([]netip.Addr, error) { return answers, nil }
		r.fetch = func(_ context.Context, target string) (string, error) {
			if target != "https://api.country.is/8.8.8.8" {
				t.Fatal("nonpublic or wrong DNS answer sent", target)
			}
			return `{"country":"US"}`, nil
		}
		result, err := r.Lookup(context.Background(), "mixed.example.net")
		if err != nil || result.IP != "8.8.8.8" {
			t.Fatal(result, err)
		}
	}
	r := New()
	r.lookup = func(context.Context, string, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("::1")}, nil
	}
	r.fetch = func(context.Context, string) (string, error) {
		t.Fatal("private-only answers contacted provider")
		return "", nil
	}
	if _, err := r.Lookup(context.Background(), "private.example.net"); err == nil {
		t.Fatal("private-only DNS accepted")
	}
}
