package web

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/netip"
	"strings"
	"time"
)

func (s *Server) resyncProbe(ctx context.Context, cfg *probeSyncConfig, uuid string) error {
	index := -1
	for i, b := range cfg.Bindings {
		if b.UUID == uuid && b.Status == "bound" {
			index = i
			break
		}
	}
	if index < 0 {
		return errors.New("请先接入该探针服务器")
	}
	b := &cfg.Bindings[index]
	m, e := s.remoteManager()
	if e != nil {
		return e
	}
	record, e := m.Record(b.ServerID)
	if e != nil {
		return errors.New("原服务器记录已删除，无法重新同步")
	}
	if stringField(record, "probeUUID") != uuid || stringField(record, "probeSource") != cfg.URL {
		return errors.New("服务器与探针关联已变化，拒绝覆盖")
	}
	var clients []probeClient
	if e = s.probeRequest(ctx, *cfg, "GET", "/api/admin/client/list", nil, &clients); e != nil {
		return e
	}
	candidates := []string{}
	seen := map[string]bool{}
	for _, c := range clients {
		if c.UUID != uuid {
			continue
		}
		for _, raw := range []string{c.IPv4, c.IPv6} {
			ip, err := netip.ParseAddr(strings.TrimSpace(raw))
			if err == nil && netguard.PublicAddress(ip) && !seen[ip.String()] {
				candidates = append(candidates, ip.String())
				seen[ip.String()] = true
			}
		}
	}
	if len(candidates) == 0 {
		return errors.New("原探针未提供有效公网 IP，保留原地址")
	}
	connection, e := m.Connection(b.ServerID)
	if e != nil {
		return e
	}
	// Prefer a still-advertised working address to avoid needless IPv4/IPv6 flips.
	for i, host := range candidates {
		if host == connection.Host {
			candidates[0], candidates[i] = candidates[i], candidates[0]
			break
		}
	}
	for _, host := range candidates {
		attempt, cancel := context.WithTimeout(ctx, 8*time.Second)
		next := connection
		next.Host = host
		client, err := remote.Connect(attempt, next)
		cancel()
		if err != nil {
			continue
		}
		client.Close()
		if _, e = m.UpdateProbeHost(record, host); e != nil {
			return e
		}
		b.Host = host
		b.Port = connection.Port
		b.Error = ""
		b.Synced = s.now().Unix()
		if e = s.writeProbeSync(*cfg); e != nil {
			return errors.New("管理地址已更新，但同步状态保存失败，请再次同步核对")
		}
		return nil
	}
	return errors.New("探针新 IP 未通过原 SSH 主机指纹和密钥验证，已保留旧地址；请检查端口、防火墙，或确认是否重装/更换了服务器")
}
