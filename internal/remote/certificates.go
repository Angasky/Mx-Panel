package remote

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/net/idna"
)

//go:embed scripts/certificate.sh
var certificateShell string

type certificateTask struct {
	id, server, domain, revision, status, message string
	created, finished                             time.Time
	dns                                           bool
}

func certificateDomain(domain string) (string, error) {
	domain = strings.ToLower(strings.TrimRight(strings.TrimSpace(domain), "."))
	var err error
	domain, err = idna.Lookup.ToASCII(domain)
	if err != nil {
		return "", errors.New("证书域名格式无效")
	}
	if len(domain) > 253 || net.ParseIP(domain) != nil || !strings.Contains(domain, ".") {
		return "", errors.New("请填写自己的有效证书域名")
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", errors.New("证书域名格式无效")
		}
		for _, ch := range label {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return "", errors.New("证书域名格式无效")
			}
		}
	}
	return domain, nil
}
func certificateRevision(record Record) string {
	fields := []any{}
	for _, key := range []string{"host", "sshPort", "sshUser", "fingerprint", "installType"} {
		fields = append(fields, record[key])
	}
	raw, _ := json.Marshal(fields)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}
func certificateScript(record Record, domain string) (string, error) {
	domain, err := certificateDomain(domain)
	if err != nil {
		return "", err
	}
	ip := net.ParseIP(value(record["host"]))
	if ip == nil || !ip.IsGlobalUnicast() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return "", errors.New("自动证书要求服务器登记为有效 IP 地址")
	}
	service := value(record["installType"])
	switch service {
	case "", "3x-ui", "x-ui", "x-panel":
		service = "x-ui"
	case "xray", "sing-box":
	default:
		return "", errors.New("此服务器类型不支持自动证书")
	}
	return "cert_domain=" + quote(domain) + "\nexpected_ip=" + quote(ip.String()) + "\ncert_dir=" + quote("/etc/mxioc-certificates/"+domain) + "\ncert_service=" + quote(service) + "\n" + strings.ReplaceAll(certificateShell, "\r\n", "\n"), nil
}

// SetJobContext attaches workers to process shutdown rather than a polling HTTP
// request. A short response must not cancel an already accepted certificate job.
func (m *Manager) SetJobContext(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.jobContext = ctx
}
func certificatePublic(task *certificateTask) Record {
	result := Record{"id": task.id, "serverId": task.server, "domain": task.domain, "serverRevision": task.revision, "status": task.status, "error": task.message, "createdAt": task.created.Unix()}
	if !task.finished.IsZero() {
		result["finishedAt"] = task.finished.Unix()
	}
	if task.status == "succeeded" {
		base := "/etc/mxioc-certificates/" + task.domain
		result["certFile"] = base + "/fullchain.pem"
		result["keyFile"] = base + "/privkey.pem"
	}
	return result
}

func (m *Manager) StartCertificate(server, domain string) (Record, error) {
	return m.StartDNSCertificate(server, domain, "", nil)
}
func (m *Manager) StartDNSCertificate(server, domain, provider string, credentials map[string]string) (Record, error) {
	prefix, err := certificateDNSPrefix(provider, credentials)
	if err != nil {
		return nil, err
	}
	domain, err = certificateDomain(domain)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	record, err := find(data, server)
	if err != nil {
		return nil, err
	}
	script, err := certificateScript(record, domain)
	if err != nil {
		return nil, err
	}
	script = prefix + script
	revision := certificateRevision(record)
	for _, task := range m.certificates {
		if task.server == server && (task.status == "queued" || task.status == "running") {
			if provider == "" && !task.dns && task.domain == domain && task.revision == revision {
				return certificatePublic(task), nil
			}
			return nil, errors.New("此服务器正在准备另一张证书，请稍后重试")
		}
	}
	for _, v := range data["jobs"].([]any) {
		job, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("任务记录损坏")
		}
		if job["serverId"] == server && job["status"] == "running" {
			return nil, errors.New("请等待服务器安装任务结束")
		}
	}
	if m.operations == nil {
		m.operations = map[string]chan struct{}{}
	}
	guard := m.operations[server]
	if guard == nil {
		guard = make(chan struct{}, 1)
		m.operations[server] = guard
	}
	if len(guard) > 0 {
		return nil, errors.New("服务器正在处理其他操作，请稍后重试")
	}
	parent := m.jobContext
	if parent == nil {
		parent = context.Background()
	}
	if err = parent.Err(); err != nil {
		return nil, errors.New("服务正在停止，未启动证书任务")
	}
	if m.certificates == nil {
		m.certificates = map[string]*certificateTask{}
	}
	if len(m.certificates) >= 64 {
		var oldest *certificateTask
		for _, task := range m.certificates {
			if task.status == "succeeded" || task.status == "failed" {
				if oldest == nil || task.created.Before(oldest.created) {
					oldest = task
				}
			}
		}
		if oldest == nil {
			return nil, errors.New("证书任务过多，请稍后重试")
		}
		delete(m.certificates, oldest.id)
	}
	raw := make([]byte, 12)
	if _, err = rand.Read(raw); err != nil {
		return nil, err
	}
	if m.certificateSlots == nil {
		m.certificateSlots = make(chan struct{}, 4)
	}
	select {
	case m.certificateSlots <- struct{}{}:
	default:
		return nil, errors.New("证书任务繁忙，请稍后重试")
	}
	guard <- struct{}{}
	task := &certificateTask{dns: provider != "", id: hex.EncodeToString(raw), server: server, domain: domain, revision: revision, status: "queued", created: time.Now()}
	m.certificates[task.id] = task
	runner := m.certificateRun
	if runner == nil {
		runner = func(ctx context.Context, c Connection, script string) (string, error) {
			return Execute(ctx, c, script, 64<<10)
		}
	}
	slots := m.certificateSlots
	go m.runCertificate(parent, task, record, script, guard, slots, runner)
	return certificatePublic(task), nil
}

func (m *Manager) runCertificate(parent context.Context, task *certificateTask, record Record, script string, guard, slots chan struct{}, runner func(context.Context, Connection, string) (string, error)) {
	defer func() { <-guard; <-slots }()
	ctx, cancel := context.WithTimeout(parent, 600*time.Second)
	defer cancel()
	m.mu.Lock()
	task.status = "running"
	m.mu.Unlock()
	connection, err := m.Connection(task.server)
	output := ""
	if err == nil {
		output, err = runner(ctx, connection, script)
	}
	if ctx.Err() != nil {
		err = errors.New("证书任务已取消或超时，尚未创建节点；重试将检查已有证书")
	}
	ready := false
	for _, line := range strings.Split(output, "\n") {
		if strings.TrimSpace(line) == "MXIOC_CERT_READY" {
			ready = true
		}
	}
	if err == nil && !ready {
		err = errors.New("远端未确认有效证书，尚未创建节点")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		data, e := m.load()
		err = e
		if err == nil {
			var current Record
			current, err = find(data, task.server)
			if err == nil && certificateRevision(current) != task.revision {
				err = errors.New("服务器连接信息已变化，未保存证书关联")
			}
			if err == nil {
				domains := []any{}
				seen := map[string]bool{}
				if existing, ok := current["certificateDomains"].([]any); ok {
					for _, v := range existing {
						if d, ok := v.(string); ok && !seen[d] {
							domains = append(domains, d)
							seen[d] = true
						}
					}
				}
				if !seen[task.domain] {
					domains = append(domains, task.domain)
				}
				if len(domains) > 32 {
					domains = domains[len(domains)-32:]
				}
				current["certificateDomains"] = domains
				if e = m.flush(data); e != nil {
					err = errors.New("证书已准备，域名记录保存失败；重试会检查已有证书")
				}
			}
		}
	}
	task.finished = time.Now()
	if err != nil {
		message := err.Error()
		if task.dns {
			message = "DNS 验证签发失败，请核对 DNS API 权限、域名、网络和远端 ACME 状态后重试"
			output = ""
		}
		if output != "" {
			message += "：" + output
		}
		for _, key := range []string{"sshPassword", "panelPassword"} {
			if secret, e := m.Secret(record, key); e == nil && secret != "" {
				message = strings.ReplaceAll(message, secret, "[REDACTED]")
			}
		}
		// Sanitize before truncation so a long credential line cannot lose its
		// identifying key while leaving the credential value in the returned tail.
		message = CleanDiagnosticLog(message)
		if tail := []rune(message); len(tail) > 2000 {
			message = string(tail[len(tail)-2000:])
		}
		task.status, task.message = "failed", message
	} else {
		task.status = "succeeded"
	}
}

func (m *Manager) CertificateJob(server, identity string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	record, err := find(data, server)
	if err != nil {
		return nil, err
	}
	task := m.certificates[identity]
	if task == nil || task.server != server {
		return nil, errors.New("证书任务不存在或服务已重启，请重新准备证书；尚未创建节点")
	}
	if task.revision != certificateRevision(record) {
		return nil, errors.New("服务器连接信息已变化，请重新准备证书")
	}
	return certificatePublic(task), nil
}

// ReadyCertificate is the handoff for native inbound creation, never accepting
// paths supplied by a browser or a job belonging to a different domain/server.
func (m *Manager) ReadyCertificate(server, identity, domain string) (Record, error) {
	domain, err := certificateDomain(domain)
	if err != nil {
		return nil, err
	}
	job, err := m.CertificateJob(server, identity)
	if err != nil {
		return nil, err
	}
	if job["domain"] != domain || job["status"] != "succeeded" {
		return nil, errors.New("证书尚未就绪或域名不匹配")
	}
	return Record{"serverName": domain, "certFile": job["certFile"], "keyFile": job["keyFile"]}, nil
}

// Provider names, environment keys and plugin digests are fixed; no user-controlled shell identifiers.
func certificateDNSPrefix(provider string, credentials map[string]string) (string, error) {
	if provider == "" {
		return "cert_dns=''\ncert_dns_hash=''\n", nil
	}
	keys := map[string][]string{"dns_cf": {"CF_Token"}, "dns_ali": {"Ali_Key", "Ali_Secret"}, "dns_dp": {"DP_Id", "DP_Key"}}
	hashes := map[string]string{"dns_cf": "a908b175d0347c2a5d76d631e509318cb73d1e552fdedb27fd5e83a4354b5dcc", "dns_ali": "6cfcca209d54747dc7b48fea9aa4a2c04a6017c4464f8f23a077e3eaa187c427", "dns_dp": "a4b5b70c81235a033c6892359b09000097b88a0792b7029d14653a5494d282de"}
	required, ok := keys[provider]
	if !ok {
		return "", errors.New("不支持的 DNS 提供商")
	}
	if len(credentials) != len(required) {
		return "", errors.New("DNS 凭据字段不完整或含未知字段")
	}
	prefix := "cert_dns=" + quote(provider) + "\ncert_dns_hash=" + quote(hashes[provider]) + "\n"
	for _, key := range required {
		value := credentials[key]
		if len(value) < 1 || len(value) > 4096 || strings.ContainsAny(value, "\x00\r\n") {
			return "", errors.New("DNS 凭据无效")
		}
		prefix += "export " + key + "=" + quote(value) + "\n"
	}
	return prefix, nil
}
