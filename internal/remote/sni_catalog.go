package remote

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
)

type sniBaseline struct {
	Domain     string `json:"domain"`
	Address    string `json:"address"`
	ServerID   string `json:"serverId"`
	ServerName string `json:"serverName"`
	Kind       string `json:"kind"`
	VerifiedAt int64  `json:"verifiedAt"`
}

// Caller holds m.mu. Only a successful full Reality scan can populate this file.
func (m *Manager) loadSNICatalog() (map[string]sniBaseline, error) {
	entries := map[string]sniBaseline{}
	raw, err := os.ReadFile(filepath.Join(m.root, "sni-catalog.json"))
	if os.IsNotExist(err) {
		return entries, nil
	}
	if err != nil {
		return nil, err
	}
	if len(raw) > 1<<20 || json.Unmarshal(raw, &entries) != nil || entries == nil || len(entries) > 200 {
		return nil, errors.New("固定 SNI 站点库损坏，请恢复备份")
	}
	for domain, entry := range entries {
		d, e := certificateDomain(domain)
		ip, ie := netip.ParseAddr(entry.Address)
		if e != nil || d != domain || entry.Domain != domain || ie != nil || !netguard.PublicAddress(ip) || entry.VerifiedAt <= 0 {
			return nil, errors.New("固定 SNI 站点库内容无效")
		}
	}
	return entries, nil
}
func (m *Manager) SNICatalog() (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := m.loadSNICatalog()
	if err != nil {
		return nil, err
	}
	rows := make([]sniBaseline, 0, len(entries))
	for _, entry := range entries {
		rows = append(rows, entry)
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].Domain < rows[j].Domain })
	return Record{"entries": rows}, nil
}
func (m *Manager) BuildSNICatalog(ctx context.Context, id string, candidates []string) (Record, error) {
	domains, err := sniDomains(candidates)
	if err != nil {
		return nil, err
	}
	result, err := m.ScanSNI(ctx, id, domains, true)
	if err != nil {
		return nil, err
	}
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entries, err := m.loadSNICatalog()
	if err != nil {
		return nil, err
	}
	for _, domain := range domains {
		delete(entries, domain)
	}
	for _, row := range result["results"].([]Record) {
		if row["ok"] == true && row["realityVerified"] == true {
			domain := value(row["domain"])
			entries[domain] = sniBaseline{domain, value(row["verifiedAddress"]), id, value(record["name"]), value(record["installType"]), time.Now().Unix()}
		}
	}
	if len(entries) > 200 {
		return nil, errors.New("固定站点最多 200 个，请减少候选数量")
	}
	raw, err := json.Marshal(entries)
	if err == nil {
		err = write(filepath.Join(m.root, "sni-catalog.json"), raw)
	}
	if err != nil {
		return nil, err
	}
	result["catalogSaved"] = true
	return result, nil
}

// TCP connect only: no DNS, TLS, HTTP request, or temporary proxy process.
func sniTCPScript(address string) (string, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !netguard.PublicAddress(ip) {
		return "", errors.New("TCP 目标必须是固定库中的公网 IP")
	}
	return "set -eu\nstart=$(date +%s%N)\ntimeout 2 bash -c " + quote("exec 3<>/dev/tcp/"+ip.String()+"/443") + " 2>/dev/null\nend=$(date +%s%N)\nprintf 'MXIOC_TCP %s\\n' \"$((end-start))\"\n", nil
}
func sniTCPLatency(raw string) (float64, bool) {
	fields := strings.Fields(raw)
	if len(fields) != 2 || fields[0] != "MXIOC_TCP" {
		return 0, false
	}
	ns, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || ns <= 0 || ns > 5e9 {
		return 0, false
	}
	return roundMetric(float64(ns) / 1e6), true
}

func (m *Manager) ScanSNITCP(ctx context.Context, id string, candidates []string) (Record, error) {
	domains, err := sniDomains(candidates)
	if err != nil {
		return nil, err
	}
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	revision := certificateRevision(record)
	m.mu.Lock()
	entries, err := m.loadSNICatalog()
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(entries) == 0 {
		return nil, errors.New("尚未建立固定站点库，请先选择一台参考服务器完整扫描一次")
	}
	connection, err := m.connectionRecord(record)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	scanner := m.sniState()
	slot, err := scanner.serverSlot(id)
	if err != nil {
		return nil, err
	}
	defer func() { scanner.mu.Lock(); slot.users--; scanner.mu.Unlock() }()
	select {
	case slot.gate <- struct{}{}:
		defer func() { <-slot.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	select {
	case scanner.slots <- struct{}{}:
		defer func() { <-scanner.slots }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	session, err := scanner.open(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	rows := make([]Record, len(domains))
	jobs := make(chan int)
	var workers sync.WaitGroup
	for n := 0; n < 8; n++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := range jobs {
				domain := domains[i]
				row := Record{"domain": domain, "ok": false, "realityVerified": false, "method": "tcp"}
				rows[i] = row
				entry, ok := entries[domain]
				if !ok {
					row["error"] = "不在固定站点库，请先用参考服务器完整验证"
					continue
				}
				row["baselineVerified"] = true
				row["baselineServer"] = entry.ServerName
				row["baselineAt"] = entry.VerifiedAt
				script, e := sniTCPScript(entry.Address)
				if e != nil {
					row["error"] = e.Error()
					continue
				}
				raw, e := session.Run(ctx, script, 4096)
				latency, ok := sniTCPLatency(raw)
				if e != nil || !ok {
					row["error"] = "TCP 443 连接失败或超时"
					continue
				}
				row["ok"] = true
				row["latencyMs"] = latency
				row["verifiedAddress"] = entry.Address
			}
		}()
	}
	for i := range domains {
		jobs <- i
	}
	close(jobs)
	workers.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	current, err := m.Record(id)
	if err != nil || certificateRevision(current) != revision {
		return nil, errors.New("服务器连接资料已变化，已丢弃测速结果")
	}
	// Keep TCP reachability separate from actual Reality proof.
	scanner.mu.Lock()
	if scanner.tcpCache == nil {
		scanner.tcpCache = map[sniCacheKey]sniCached{}
	}
	for key, entry := range scanner.tcpCache {
		if scanner.now().Sub(entry.at) >= 10*time.Minute {
			delete(scanner.tcpCache, key)
		}
	}
	for _, row := range rows {
		entry, exists := entries[value(row["domain"])]
		if !exists {
			continue
		}
		key := sniCacheKey{id, revision, entry.Domain, entry.Address}
		delete(scanner.tcpCache, key)
		if row["ok"] == true {
			if len(scanner.tcpCache) >= 2048 {
				for k := range scanner.tcpCache {
					delete(scanner.tcpCache, k)
					break
				}
			}
			scanner.tcpCache[key] = sniCached{scanner.now(), true}
		}
	}
	scanner.mu.Unlock()
	sort.SliceStable(rows, func(i, j int) bool {
		a, aok := rows[i]["latencyMs"].(float64)
		b, bok := rows[j]["latencyMs"].(float64)
		return aok && (!bok || a < b)
	})
	return Record{"results": rows, "method": "tcp"}, nil
}
