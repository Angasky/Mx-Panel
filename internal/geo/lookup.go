package geo

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"github.com/Angasky/dingzhi-ban/internal/subsource"
)

type Country struct{ Code, IP string }
type cached struct {
	value Country
	at    time.Time
}
type Resolver struct {
	mu       sync.Mutex
	cache    map[string]cached
	next     time.Time
	interval time.Duration
	slots    chan struct{}
	lookup   func(context.Context, string, string) ([]netip.Addr, error)
	fetch    func(context.Context, string) (string, error)
}

func New() *Resolver {
	return &Resolver{cache: map[string]cached{}, interval: 120 * time.Millisecond, slots: make(chan struct{}, 8), lookup: net.DefaultResolver.LookupNetIP, fetch: subsource.NewClient().Fetch}
}
func (r *Resolver) Lookup(ctx context.Context, host string) (Country, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return Country{}, errors.New("服务器地址为空")
	}
	var addresses []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addresses = []netip.Addr{ip}
	} else {
		var err error
		addresses, err = r.lookup(ctx, "ip", host)
		if err != nil {
			return Country{}, errors.New("节点域名解析失败")
		}
	}
	if len(addresses) == 0 {
		return Country{}, errors.New("节点没有解析到公网 IP")
	}
	for _, address := range addresses {
		if !netguard.PublicAddress(address) {
			return Country{}, errors.New("节点地址包含非公网 IP")
		}
	}
	address := addresses[0].Unmap().String()
	now := time.Now()
	r.mu.Lock()
	if entry, ok := r.cache[address]; ok && now.Sub(entry.at) >= 0 && now.Sub(entry.at) < 7*24*time.Hour {
		r.mu.Unlock()
		return entry.value, nil
	}
	r.mu.Unlock()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return Country{}, ctx.Err()
	}
	r.mu.Lock()
	delay := time.Until(r.next)
	if delay < 0 {
		delay = 0
	}
	r.next = time.Now().Add(delay + r.interval)
	r.mu.Unlock()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
		return Country{}, ctx.Err()
	}
	body, err := r.fetch(ctx, "https://api.country.is/"+address)
	if err != nil {
		return Country{}, errors.New("IP 国家识别服务暂不可用")
	}
	var payload struct {
		Country string `json:"country"`
	}
	if len(body) > 65536 || json.Unmarshal([]byte(body), &payload) != nil {
		return Country{}, errors.New("IP 国家识别响应无效")
	}
	code := strings.ToUpper(payload.Country)
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return Country{}, errors.New("IP 国家识别未返回有效国家")
	}
	value := Country{code, address}
	r.mu.Lock()
	if len(r.cache) >= 2048 {
		for key := range r.cache {
			delete(r.cache, key)
			break
		}
	}
	r.cache[address] = cached{value, time.Now()}
	r.mu.Unlock()
	return value, nil
}
