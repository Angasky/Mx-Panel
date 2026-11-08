// Package netprobe measures TCP connection establishment, never application traffic.
package netprobe

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type Target struct {
	Name string `json:"name"`
	Host string `json:"host"`
	Port int    `json:"port"`
}
type Result struct {
	Name         string   `json:"name"`
	Time         int64    `json:"time"`
	OK           bool     `json:"ok"`
	Milliseconds *float64 `json:"milliseconds"`
}

func Validate(targets []Target) error {
	if len(targets) > 6 {
		return errors.New("最多设置 6 个 TCP 探测目标")
	}
	seen := map[string]bool{}
	for _, t := range targets {
		if !utf8.ValidString(t.Name) || len([]rune(t.Name)) < 1 || len([]rune(t.Name)) > 40 || strings.ContainsFunc(t.Name, unicode.IsControl) || seen[t.Name] {
			return errors.New("探测名称需为不重复的 1–40 个字符")
		}
		seen[t.Name] = true
		if t.Port < 1 || t.Port > 65535 || len(t.Host) == 0 || len(t.Host) > 253 || strings.TrimSpace(t.Host) != t.Host || strings.ContainsAny(t.Host, "/\\@% \t\r\n") {
			return errors.New("探测地址或端口无效")
		}
		if ip := net.ParseIP(strings.Trim(t.Host, "[]")); ip != nil && !publicIP(ip) {
			return errors.New("探测地址必须为公网地址")
		}
	}
	return nil
}
func publicIP(ip net.IP) bool {
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() || ip.IsMulticast() || ip.Equal(net.IPv4bcast) {
		return false
	}
	address, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	address = address.Unmap()
	for _, cidr := range []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "198.18.0.0/15", "240.0.0.0/4"} {
		if netip.MustParsePrefix(cidr).Contains(address) {
			return false
		}
	}
	return true
}

func Measure(parent context.Context, targets []Target) []Result {
	if Validate(targets) != nil {
		return nil
	}
	results := make([]Result, len(targets))
	done := make(chan int, len(targets))
	for i, target := range targets {
		go func(i int, t Target) {
			defer func() { done <- i }()
			ctx, cancel := context.WithTimeout(parent, 3*time.Second)
			defer cancel()
			r := Result{Name: t.Name, Time: time.Now().Unix()}
			defer func() { results[i] = r }()
			addresses, e := net.DefaultResolver.LookupIPAddr(ctx, strings.Trim(t.Host, "[]"))
			if e != nil {
				return
			}
			for _, a := range addresses {
				if !publicIP(a.IP) {
					return
				}
			}
			for _, a := range addresses {
				start := time.Now()
				conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(a.IP.String(), strconv.Itoa(t.Port)))
				if e == nil {
					conn.Close()
					elapsed := float64(time.Since(start).Microseconds()) / 1000
					r.OK = true
					r.Milliseconds = &elapsed
					return
				}
			}
		}(i, target)
	}
	for range targets {
		<-done
	}
	return results
}
