package web

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"golang.org/x/crypto/ssh"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type probeClient struct {
	UUID   string `json:"uuid"`
	Name   string `json:"name"`
	IPv4   string `json:"ipv4"`
	IPv6   string `json:"ipv6"`
	OS     string `json:"os"`
	Region string `json:"region"`
}
type probeBinding struct {
	KeyFingerprint string `json:"keyFingerprint"`
	UUID           string `json:"uuid"`
	Name           string `json:"name"`
	Host           string `json:"host"`
	Port           int    `json:"port"`
	Task           string `json:"task"`
	Secret         string `json:"secret,omitempty"`
	Status         string `json:"status"`
	ServerID       string `json:"serverId,omitempty"`
	Created        int64  `json:"created"`
}
type probeSyncConfig struct {
	URL      string         `json:"url"`
	Secret   string         `json:"secret,omitempty"`
	Bindings []probeBinding `json:"bindings"`
}

var probeID = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

func (s *Server) readProbeSync() (probeSyncConfig, error) {
	var v probeSyncConfig
	b, e := os.ReadFile(filepath.Join(s.options.Root, "probe-sync.json"))
	if os.IsNotExist(e) {
		return v, nil
	}
	if e != nil {
		return v, e
	}
	if len(b) > 2<<20 {
		return v, errors.New("探针同步记录过大")
	}
	e = json.Unmarshal(b, &v)
	return v, e
}
func (s *Server) writeProbeSync(v probeSyncConfig) error {
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".probe-sync-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "probe-sync.json"))
}
func probeHTTPClient() *http.Client {
	return &http.Client{Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("探针接口不允许跳转") }, Transport: &http.Transport{Proxy: nil, TLSHandshakeTimeout: 8 * time.Second, ResponseHeaderTimeout: 10 * time.Second, DisableKeepAlives: true, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, e := net.SplitHostPort(address)
		if e != nil {
			return nil, e
		}
		ips, e := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if e != nil {
			return nil, e
		}
		for _, ip := range ips {
			if !netguard.PublicAddress(ip) {
				return nil, errors.New("探针地址必须为公网 HTTPS")
			}
		}
		for _, ip := range ips {
			c, e := (&net.Dialer{Timeout: 8 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if e == nil {
				return c, nil
			}
		}
		return nil, errors.New("探针连接失败")
	}}}
}
func (s *Server) probeRequest(ctx context.Context, cfg probeSyncConfig, method, path string, input any, out any) error {
	m, e := s.remoteManager()
	if e != nil {
		return e
	}
	secret, e := m.OpenUser(cfg.Secret)
	if e != nil {
		return errors.New("请先配置探针 API Key")
	}
	var body []byte
	if input != nil {
		body, _ = json.Marshal(input)
	}
	req, e := http.NewRequestWithContext(ctx, method, cfg.URL+path, bytes.NewReader(body))
	if e != nil {
		return errors.New("探针地址无效")
	}
	req.Header.Set("Authorization", "Bearer "+stringField(secret, "key"))
	req.Header.Set("Content-Type", "application/json")
	client := s.probeHTTP
	if client == nil {
		client = probeHTTPClient()
	}
	res, e := client.Do(req)
	if e != nil {
		return errors.New("探针连接失败，请检查地址、证书和网络")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return errors.New("探针接口拒绝请求（HTTP " + strconv.Itoa(res.StatusCode) + "），请检查 API Key、远程执行权限和二次验证设置")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, (2<<20)+1))
	if e != nil || len(b) > 2<<20 {
		return errors.New("探针响应过大或读取失败")
	}
	if out == nil {
		return nil
	}
	if json.Unmarshal(b, out) != nil {
		return errors.New("探针响应格式不兼容")
	}
	return nil
}
func probeBootstrap(public string, port int) string {
	return `set -eu
[ "$(id -u)" = 0 ] || { echo 'MX_SYNC_ERROR=Agent must run as root'; exit 1; }
command -v ssh-keygen >/dev/null
command -v flock >/dev/null
sshd_bin=$(command -v sshd || true)
[ -n "$sshd_bin" ] || sshd_bin=/usr/sbin/sshd
[ -x "$sshd_bin" ]
"$sshd_bin" -t
"$sshd_bin" -T | grep -Eq '^pubkeyauthentication yes$'
"$sshd_bin" -T | grep -Eq '^permitrootlogin (yes|without-password|prohibit-password)$'
"$sshd_bin" -T | grep -Fx 'port ` + strconv.Itoa(port) + `' >/dev/null
"$sshd_bin" -T | grep -E '^authorizedkeysfile ' | grep -Eq '(^| )\.ssh/authorized_keys( |$)'
[ ! -L /root/.ssh ]
[ ! -L /root/.ssh/authorized_keys ]
[ ! -e /root/.ssh/authorized_keys ] || [ -f /root/.ssh/authorized_keys ]
mkdir -p /root/.ssh
chmod 700 /root/.ssh
exec 9>/root/.ssh/mx-panel-sync.lock
flock -w 10 9
key='` + strings.TrimSpace(public) + ` mx-panel-probe-sync'
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qxF "$key" /root/.ssh/authorized_keys || printf '\n%s\n' "$key" >> /root/.ssh/authorized_keys
for file in /etc/ssh/ssh_host_*_key.pub; do
 [ -f "$file" ] || continue
 ssh-keygen -lf "$file" -E sha256 | awk '{print "MX_SYNC_FP=" $2}'
done
printf 'MX_SYNC_READY\n'
`
}
func (s *Server) probeSyncRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/probe-sync" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.probeSyncMu.Lock()
	defer s.probeSyncMu.Unlock()
	cfg, e := s.readProbeSync()
	if e != nil {
		problem(w, 500, "探针同步配置读取失败")
		return true
	}
	fail := func(e error) bool { problem(w, 400, e.Error()); return true }
	if r.Method == "POST" {
		var in struct {
			Task      string `json:"task"`
			Action    string `json:"action"`
			URL       string `json:"url"`
			Key       string `json:"key"`
			UUID      string `json:"uuid"`
			Port      int    `json:"port"`
			Confirmed bool   `json:"confirmed"`
		}
		if readJSON(w, r, &in) != nil {
			return true
		}
		m, e := s.remoteManager()
		if e != nil {
			return fail(e)
		}
		switch in.Action {
		case "configure":
			u, e := url.Parse(strings.TrimRight(strings.TrimSpace(in.URL), "/"))
			if e != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Path != "" {
				return fail(errors.New("请输入探针根地址，例如 https://monitor.mxioc.com"))
			}
			if cfg.URL != "" && cfg.URL != u.String() && len(cfg.Bindings) > 0 {
				return fail(errors.New("已有接入记录，不可直接更换探针来源"))
			}
			if in.Key != "" {
				if len(in.Key) < 12 || len(in.Key) > 4096 || strings.ContainsAny(in.Key, "\r\n") {
					return fail(errors.New("API Key 格式无效"))
				}
				cfg.Secret, e = m.SealUser(map[string]any{"key": in.Key})
				if e != nil {
					return fail(e)
				}
			}
			cfg.URL = u.String()
			var clients []probeClient
			if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/client/list", nil, &clients); e != nil {
				return fail(e)
			}
			if e = s.writeProbeSync(cfg); e != nil {
				return fail(errors.New("探针配置保存失败"))
			}
		case "bind":
			if !in.Confirmed || !probeID.MatchString(in.UUID) || in.Port < 1 || in.Port > 65535 {
				return fail(errors.New("请确认接入并指定有效 SSH 端口"))
			}
			for _, b := range cfg.Bindings {
				if b.UUID == in.UUID {
					return fail(errors.New("该服务器已有接入记录，请刷新任务，不要重复派发"))
				}
			}
			if len(cfg.Bindings) >= 200 {
				return fail(errors.New("最多接入 200 台探针服务器"))
			}
			var clients []probeClient
			if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/client/list", nil, &clients); e != nil {
				return fail(e)
			}
			var selected *probeClient
			for i := range clients {
				if clients[i].UUID == in.UUID {
					selected = &clients[i]
					break
				}
			}
			if selected == nil {
				return fail(errors.New("探针服务器不存在"))
			}
			if strings.TrimSpace(selected.Name) == "" || len(selected.Name) > 300 {
				return fail(errors.New("探针服务器名称为空或超过 300 字节，请先在探针修改"))
			}
			host := ""
			for _, raw := range []string{selected.IPv4, selected.IPv6} {
				ip, e := netip.ParseAddr(strings.TrimSpace(raw))
				if e == nil && netguard.PublicAddress(ip) {
					host = ip.String()
					break
				}
			}
			if host == "" {
				return fail(errors.New("探针没有可用的公网 IP"))
			}
			rows, e := m.List()
			if e != nil {
				return fail(e)
			}
			for _, row := range rows {
				if stringField(row, "host") == host {
					return fail(errors.New("此 IP 已在服务器列表登记，请使用现有记录，避免重复管理"))
				}
			}
			pub, private, e := ed25519.GenerateKey(rand.Reader)
			if e != nil {
				return fail(e)
			}
			block, e := ssh.MarshalPrivateKey(private, "mx-panel-probe-sync")
			if e != nil {
				return fail(e)
			}
			key, e := ssh.NewPublicKey(pub)
			if e != nil {
				return fail(e)
			}
			sealed, e := m.SealUser(map[string]any{"private": string(pem.EncodeToMemory(block))})
			if e != nil {
				return fail(e)
			}
			binding := probeBinding{KeyFingerprint: ssh.FingerprintSHA256(key), UUID: in.UUID, Name: selected.Name, Host: host, Port: in.Port, Secret: sealed, Status: "dispatching", Created: s.now().Unix()}
			cfg.Bindings = append(cfg.Bindings, binding)
			// Persist intent and key before external side effects. Ambiguous dispatch is never retried.
			if e = s.writeProbeSync(cfg); e != nil {
				return fail(errors.New("接入意图保存失败，未发送任务"))
			}
			var result struct {
				Data struct {
					Task string `json:"task_id"`
				} `json:"data"`
			}
			e = s.probeRequest(r.Context(), cfg, "POST", "/api/admin/task/exec", map[string]any{"clients": []string{in.UUID}, "command": probeBootstrap(string(ssh.MarshalAuthorizedKey(key)), in.Port)}, &result)
			b := &cfg.Bindings[len(cfg.Bindings)-1]
			if e != nil || !probeID.MatchString(result.Data.Task) {
				b.Status = "unknown"
				_ = s.writeProbeSync(cfg)
				return fail(errors.New("派发结果未确认；请在探针任务记录核对，系统不会自动重复授权"))
			}
			b.Task = result.Data.Task
			b.Status = "pending"
			if e = s.writeProbeSync(cfg); e != nil {
				return fail(errors.New("任务已派发但记录保存失败，请核对探针任务"))
			}

		case "recover", "retry":
			if !in.Confirmed {
				return fail(errors.New("请确认任务恢复操作"))
			}
			index := -1
			for i := range cfg.Bindings {
				if cfg.Bindings[i].UUID == in.UUID {
					index = i
					break
				}
			}
			if index < 0 {
				return fail(errors.New("接入记录不存在"))
			}
			b := &cfg.Bindings[index]
			if b.Status == "bound" || b.Secret == "" {
				return fail(errors.New("此记录不能重新派发"))
			}
			secret, e := m.OpenUser(b.Secret)
			if e != nil {
				return fail(errors.New("接入密钥读取失败"))
			}
			signer, e := ssh.ParsePrivateKey([]byte(stringField(secret, "private")))
			if e != nil {
				return fail(errors.New("接入密钥无效"))
			}
			script := probeBootstrap(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), b.Port)
			if in.Action == "recover" {
				if !probeID.MatchString(in.Task) {
					return fail(errors.New("请输入原探针中的任务编号"))
				}
				var task struct {
					Data struct {
						Task    string   `json:"task_id"`
						Command string   `json:"command"`
						Clients []string `json:"clients"`
					} `json:"data"`
				}
				if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/task/"+in.Task, nil, &task); e != nil {
					return fail(e)
				}
				if task.Data.Task != in.Task || len(task.Data.Clients) != 1 || task.Data.Clients[0] != b.UUID || task.Data.Command != script {
					return fail(errors.New("任务的目标服务器或授权公钥不匹配"))
				}
				b.Task = in.Task
				b.Status = "pending"
			} else {
				if b.Status != "failed" {
					return fail(errors.New("仅已确认失败的任务可重试，未知任务请先恢复关联"))
				}
				b.Status = "dispatching"
				b.Task = ""
				if e = s.writeProbeSync(cfg); e != nil {
					return fail(errors.New("派发意图保存失败"))
				}
				var task struct {
					Data struct {
						Task string `json:"task_id"`
					} `json:"data"`
				}
				e = s.probeRequest(r.Context(), cfg, "POST", "/api/admin/task/exec", map[string]any{"clients": []string{b.UUID}, "command": script}, &task)
				if e != nil || !probeID.MatchString(task.Data.Task) {
					b.Status = "unknown"
					_ = s.writeProbeSync(cfg)
					return fail(errors.New("重试派发结果未知，请恢复关联后核对"))
				}
				b.Task = task.Data.Task
				b.Status = "pending"
			}
			if e = s.writeProbeSync(cfg); e != nil {
				return fail(errors.New("任务记录保存失败"))
			}
		case "check":
			index := -1
			for i := range cfg.Bindings {
				if cfg.Bindings[i].UUID == in.UUID {
					index = i
					break
				}
			}
			if index < 0 {
				return fail(errors.New("接入记录不存在"))
			}
			b := &cfg.Bindings[index]
			if b.Status == "bound" {
				break
			}
			if b.Task == "" {
				return fail(errors.New("任务编号未知，请先核对探针任务记录"))
			}
			var result struct {
				Data struct {
					Result   string `json:"result"`
					ExitCode *int   `json:"exit_code"`
					Client   string `json:"client"`
					Task     string `json:"task_id"`
				} `json:"data"`
			}
			if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/task/"+b.Task+"/result/"+b.UUID, nil, &result); e != nil {
				return fail(e)
			}
			if result.Data.Client != b.UUID || result.Data.Task != b.Task {
				return fail(errors.New("探针任务身份不匹配"))
			}
			if result.Data.ExitCode == nil {
				break
			}
			if *result.Data.ExitCode != 0 || !strings.Contains(result.Data.Result, "MX_SYNC_READY") {
				b.Status = "failed"
				_ = s.writeProbeSync(cfg)
				return fail(errors.New("探针授权失败，请在原探针查看任务输出；需要 root Agent 和支持密钥登录的 SSH"))
			}
			secret, e := m.OpenUser(b.Secret)
			if e != nil {
				return fail(errors.New("接入密钥读取失败"))
			}
			private := stringField(secret, "private")
			connection := remote.Connection{Host: b.Host, Port: b.Port, User: "root", PrivateKey: private}
			fp, e := remote.Probe(r.Context(), connection)
			if e != nil {
				return fail(e)
			}
			trusted := false
			for _, line := range strings.Split(result.Data.Result, "\n") {
				if strings.TrimSpace(line) == "MX_SYNC_FP="+fp {
					trusted = true
				}
			}
			if !trusted {
				return fail(errors.New("SSH 主机指纹与探针返回值不匹配，拒绝接入"))
			}
			connection.Fingerprint = fp
			client, e := remote.Connect(r.Context(), connection)
			if e != nil {
				return fail(e)
			}
			client.Close()
			// A repeated check after a crash reuses the same registration, never recreates a server.
			rows, e := m.List()
			if e != nil {
				return fail(e)
			}
			for _, row := range rows {
				if stringField(row, "probeSource") == cfg.URL && stringField(row, "probeUUID") == b.UUID {
					b.ServerID = stringField(row, "id")
				}
			}
			if b.ServerID == "" {
				row, e := m.Save(remote.Record{"name": b.Name, "host": b.Host, "sshPort": b.Port, "sshUser": "root", "sshPrivateKey": private, "fingerprint": fp, "installType": "xray", "connectionMode": "install", "probeSource": cfg.URL, "probeUUID": b.UUID})
				if e != nil {
					return fail(e)
				}
				b.ServerID = stringField(row, "id")
			}
			b.Status = "bound"
			b.Secret = ""
			if e = s.writeProbeSync(cfg); e != nil {
				return fail(errors.New("服务器已登记但同步状态保存失败，请刷新核对"))
			}
		default:
			return fail(errors.New("同步操作无效"))
		}
	}
	var clients []probeClient
	connectionError := ""
	if cfg.Secret != "" {
		if e = s.probeRequest(r.Context(), cfg, "GET", "/api/admin/client/list", nil, &clients); e != nil {
			connectionError = e.Error()
		}
	}
	seen := map[string]bool{}
	for _, c := range clients {
		seen[c.UUID] = true
	}
	for _, b := range cfg.Bindings {
		if !seen[b.UUID] {
			clients = append(clients, probeClient{UUID: b.UUID, Name: b.Name, IPv4: b.Host, OS: "已保存的接入记录"})
		}
	}
	for i := range cfg.Bindings {
		cfg.Bindings[i].Secret = ""
	}
	respond(w, 200, map[string]any{"url": cfg.URL, "configured": cfg.Secret != "", "clients": clients, "bindings": cfg.Bindings, "connectionError": connectionError})
	return true
}
