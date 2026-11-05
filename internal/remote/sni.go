package remote

import (
	"context"
	"errors"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"golang.org/x/crypto/ssh"
)

type sniSession interface {
	Run(context.Context, string, int) (string, error)
	Close() error
}
type sshSNISession struct {
	client     *ssh.Client
	connection Connection
	stop       chan struct{}
	once       sync.Once
}

func (s *sshSNISession) Run(ctx context.Context, script string, limit int) (string, error) {
	return executeClient(ctx, s.client, s.connection, script, limit)
}
func (s *sshSNISession) Close() error { s.once.Do(func() { close(s.stop) }); return s.client.Close() }

type sniCacheKey struct{ server, revision, domain, address string }
type sniCached struct {
	at time.Time
	ok bool
}
type sniServerSlot struct {
	gate  chan struct{}
	users int
}

type sniScanner struct {
	mu      sync.Mutex
	slots   chan struct{}
	servers map[string]*sniServerSlot
	cache   map[sniCacheKey]sniCached
	now     func() time.Time
	open    func(context.Context, Connection) (sniSession, error)
}

func newSNIScanner() *sniScanner {
	return &sniScanner{slots: make(chan struct{}, 4), servers: map[string]*sniServerSlot{}, cache: map[sniCacheKey]sniCached{}, now: time.Now, open: func(ctx context.Context, c Connection) (sniSession, error) {
		client, err := Connect(ctx, c)
		if err != nil {
			return nil, err
		}
		session := &sshSNISession{client: client, connection: c, stop: make(chan struct{})}
		// NewSession itself can wait for an SSH reply. Close this scan's private
		// connection on cancellation, even before executeClient starts its Run wait.
		go func() {
			select {
			case <-ctx.Done():
				session.Close()
			case <-session.stop:
			}
		}()
		return session, nil
	}}
}
func (m *Manager) sniState() *sniScanner {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.sni == nil {
		m.sni = newSNIScanner()
	}
	return m.sni
}
func (s *sniScanner) serverSlot(id string) (*sniServerSlot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if slot := s.servers[id]; slot != nil {
		slot.users++
		return slot, nil
	}
	if len(s.servers) >= 128 {
		for key, slot := range s.servers {
			if slot.users == 0 {
				delete(s.servers, key)
				break
			}
		}
	}
	if len(s.servers) >= 128 {
		return nil, errors.New("SNI 任务过多，请稍后重试")
	}
	slot := &sniServerSlot{gate: make(chan struct{}, 2), users: 1}
	s.servers[id] = slot
	return slot, nil
}
func (s *sniScanner) cached(key sniCacheKey, force bool) (bool, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if force {
		return false, false
	}
	entry, ok := s.cache[key]
	ttl := 15 * time.Second
	if entry.ok {
		ttl = 10 * time.Minute
	}
	if !ok || s.now().Sub(entry.at) < 0 || s.now().Sub(entry.at) >= ttl {
		delete(s.cache, key)
		return false, false
	}
	return entry.ok, true
}
func (s *sniScanner) remember(key sniCacheKey, ok bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cache) >= 2048 {
		var oldest sniCacheKey
		var when time.Time
		first := true
		for k, v := range s.cache {
			if first || !v.at.After(when) {
				oldest, when = k, v.at
				first = false
			}
		}
		delete(s.cache, oldest)
	}
	s.cache[key] = sniCached{s.now(), ok}
}

func (s *sniScanner) invalidate(server, revision string, domains []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	wanted := map[string]bool{}
	for _, domain := range domains {
		wanted[domain] = true
	}
	for key := range s.cache {
		if key.server == server && key.revision == revision && wanted[key.domain] {
			delete(s.cache, key)
		}
	}
}

func sniDomains(candidates []string) ([]string, error) {
	if len(candidates) < 1 || len(candidates) > 20 {
		return nil, errors.New("每次测试 1–20 个 SNI 域名")
	}
	domains := []string{}
	seen := map[string]bool{}
	for _, input := range candidates {
		domain, err := certificateDomain(input)
		if err != nil {
			return nil, errors.New("SNI 域名格式无效，请使用完整域名或 Punycode")
		}
		if !seen[domain] {
			domains = append(domains, domain)
			seen[domain] = true
		}
	}
	return domains, nil
}
func sniResolveScript(domains []string) string {
	script := "set -eu\ncommand -v curl >/dev/null && command -v getent >/dev/null && command -v timeout >/dev/null || exit 12\n# MXIOC_SNI_DNS\n"
	for i, domain := range domains {
		if i%4 == 0 {
			script += "pids=''\n"
		}
		script += "timeout 3 getent ahosts " + quote(domain) + " | awk -v host=" + quote(domain) + " '{print host, $1}' &\npids=\"$pids $!\"\n"
		if i%4 == 3 || i == len(domains)-1 {
			script += "for pid in $pids; do wait \"$pid\" || true; done\n"
		}
	}
	return script
}
func sniAddresses(raw string, domains []string) map[string][]netip.Addr {
	result := map[string][]netip.Addr{}
	seen := map[string]map[netip.Addr]bool{}
	for _, domain := range domains {
		seen[domain] = map[netip.Addr]bool{}
	}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 || seen[fields[0]] == nil {
			continue
		}
		ip, err := netip.ParseAddr(fields[1])
		if err != nil {
			continue
		}
		ip = ip.Unmap()
		if !seen[fields[0]][ip] {
			seen[fields[0]][ip] = true
			result[fields[0]] = append(result[fields[0]], ip)
		}
	}
	for domain, addresses := range result {
		sort.Slice(addresses, func(i, j int) bool {
			if addresses[i].Is4() != addresses[j].Is4() {
				return addresses[i].Is4()
			}
			return addresses[i].Less(addresses[j])
		})
		result[domain] = addresses
	}
	return result
}
func sniTLSScript(domain string, address netip.Addr) string {
	ip := address.String()
	if address.Is6() {
		ip = "[" + ip + "]"
	}
	return "curl --disable --silent --show-error --head --output /dev/null --noproxy '*' --proto '=https' --tlsv1.3 --tls-max 1.3 --connect-timeout 4 --max-time 6 --resolve " + quote(domain+":443:"+ip) + " --write-out '\nMXIOC_TLS %{time_appconnect}\n' " + quote("https://"+domain+"/")
}
func sniTLSLatency(raw string) (float64, bool) {
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == "MXIOC_TLS" {
			n, err := finiteNumber(fields[1])
			if err == nil && n > 0 && n <= 60 {
				return roundMetric(n * 1000), true
			}
		}
	}
	return 0, false
}
func parseRealityResults(raw string, total int) (map[int]bool, error) {
	result := map[int]bool{}
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if fields[0] == "MXIOC_REALITY_ERROR" {
			return nil, errors.New(strings.Join(fields[1:], " "))
		}
		if fields[0] != "MXIOC_REALITY_RESULT" {
			continue
		}
		if len(fields) != 3 {
			return nil, errors.New("output")
		}
		index, err := strconv.Atoi(fields[1])
		if err != nil || index < 0 || index >= total {
			return nil, errors.New("output")
		}
		if _, exists := result[index]; exists {
			return nil, errors.New("output")
		}
		if fields[2] != "OK" && fields[2] != "FAIL" {
			return nil, errors.New("output")
		}
		result[index] = fields[2] == "OK"
	}
	return result, nil
}

func (m *Manager) ScanSNI(ctx context.Context, id string, candidates []string, force bool) (Record, error) {
	domains, err := sniDomains(candidates)
	if err != nil {
		return nil, err
	}
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	revision := certificateRevision(record)
	connection, err := m.connectionRecord(record)
	if err != nil {
		return nil, err
	}
	// Reject connection identity changes before starting queued network work.
	latest, err := m.Record(id)
	if err != nil || certificateRevision(latest) != revision {
		return nil, errors.New("服务器连接资料已变化，请重试")
	}
	ctx, cancel := context.WithTimeout(ctx, 160*time.Second)
	defer cancel()
	scanner := m.sniState()
	if force {
		scanner.invalidate(id, revision, domains)
	}
	slot, err := scanner.serverSlot(id)
	if err != nil {
		return nil, err
	}
	defer func() { scanner.mu.Lock(); slot.users--; scanner.mu.Unlock() }()
	select {
	case slot.gate <- struct{}{}:
		defer func() { <-slot.gate }()
	case <-ctx.Done():
		return nil, errors.New("SNI 扫描已取消")
	}
	select {
	case scanner.slots <- struct{}{}:
		defer func() { <-scanner.slots }()
	case <-ctx.Done():
		return nil, errors.New("SNI 扫描已取消")
	}
	session, err := scanner.open(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer session.Close()
	output, err := session.Run(ctx, sniResolveScript(domains), 128<<10)
	if err != nil {
		return nil, errors.New("服务器 DNS 读取失败，请检查 curl、getent、timeout 和 SSH 连接")
	}
	addresses := sniAddresses(output, domains)
	rows := make([]Record, len(domains))
	chosen := make([]string, len(domains))
	var workers sync.WaitGroup
	tasks := make(chan int)
	for worker := 0; worker < 5; worker++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for index := range tasks {
				domain := domains[index]
				row := Record{"domain": domain, "ok": false, "realityVerified": false, "method": "curl"}
				rows[index] = row
				candidates := addresses[domain]
				valid := len(candidates) > 0
				for _, ip := range candidates {
					if !netguard.PublicAddress(ip) {
						valid = false
					}
				}
				if !valid {
					row["error"] = "目标未解析到公网地址或解析含非公网地址"
					continue
				}
				if len(candidates) > 3 {
					candidates = candidates[:3]
				}
				for _, ip := range candidates {
					if ctx.Err() != nil {
						break
					}
					raw, err := session.Run(ctx, sniTLSScript(domain, ip), 16<<10)
					if latency, ok := sniTLSLatency(raw); err == nil && ok {
						row["tls"] = "TLSv1.3"
						row["latencyMs"] = latency
						chosen[index] = ip.String()
						break
					}
				}
				if chosen[index] == "" {
					row["error"] = "TLS 1.3 握手或证书校验失败"
				}
			}
		}()
	}
	for index := range domains {
		tasks <- index
	}
	close(tasks)
	workers.Wait()
	pending := []sniTarget{}
	indices := []int{}
	for i, row := range rows {
		if chosen[i] == "" {
			continue
		}
		key := sniCacheKey{id, revision, domains[i], chosen[i]}
		if ok, hit := scanner.cached(key, force); hit {
			row["ok"], row["realityVerified"], row["cached"] = ok, ok, true
			continue
		}
		indices = append(indices, i)
		pending = append(pending, sniTarget{domains[i], chosen[i]})
	}
	readings := map[int]bool{}
	var probeErr error
	if len(pending) > 0 && ctx.Err() == nil {
		for attempt := 0; attempt < 2; attempt++ {
			script, err := realityProbeScriptForCore(value(record["installType"]), pending)
			if err != nil {
				probeErr = err
				break
			}
			raw, err := session.Run(ctx, script, 128<<10)
			if err != nil {
				probeErr = errors.New("execute")
				break
			}
			readings, probeErr = parseRealityResults(raw, len(pending))
			if probeErr == nil || probeErr.Error() != "ports" {
				break
			}
		}
		messages := map[string]string{"tools": "服务器缺少 curl 或 timeout", "kernel": "服务器未安装可用的 Xray 验证内核", "startup": "隔离测试内核启动失败，请重试扫描", "ports": "随机测试端口已占用，请重试扫描"}
		if record["installType"] == "sing-box" {
			messages["kernel"] = "服务器未安装可用的 sing-box 或 Xray 验证内核"
		}
		for index, rowIndex := range indices {
			row := rows[rowIndex]
			if probeErr != nil {
				message := messages[probeErr.Error()]
				if message == "" {
					message = "隔离 Reality 验证未完成，请重试"
				}
				row["error"] = message
				continue
			}
			ok, present := readings[index]
			if !present {
				row["error"] = "隔离测试未返回此目标结果，请重试"
				continue
			}
			row["ok"], row["realityVerified"] = ok, ok
		}
	}
	if ctx.Err() != nil {
		return nil, errors.New("SNI 扫描超时或已取消")
	}
	current, err := m.Record(id)
	if err != nil || certificateRevision(current) != revision {
		return nil, errors.New("服务器连接资料已变化，已丢弃扫描结果")
	}
	for index, rowIndex := range indices {
		if probeErr == nil {
			if ok, present := readings[index]; present {
				scanner.remember(sniCacheKey{id, revision, domains[rowIndex], chosen[rowIndex]}, ok)
			}
		}
	}
	for i, row := range rows {
		if row["ok"] == true && row["realityVerified"] == true {
			row["verifiedAddress"] = chosen[i]
		} else if row["error"] == nil {
			row["error"] = "TLS 可连接，但两次实际 Reality 握手未通过；不提供选择"
		}
	}
	sort.SliceStable(rows, func(i, j int) bool {
		a, aok := rows[i]["latencyMs"].(float64)
		b, bok := rows[j]["latencyMs"].(float64)
		if !aok {
			return false
		}
		if !bok {
			return true
		}
		return a < b
	})
	return Record{"results": rows, "method": "curl"}, nil
}
