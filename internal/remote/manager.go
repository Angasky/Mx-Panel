package remote

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

type Manager struct {
	root, path       string
	key              []byte
	mu               sync.Mutex
	operations       map[string]chan struct{}
	panels           map[string]*cachedPanel
	monitor          *hostMonitor
	sni              *sniScanner
	certificates     map[string]*certificateTask
	certificateSlots chan struct{}
	jobContext       context.Context
	certificateRun   func(context.Context, Connection, string) (string, error)
	installRun       func(context.Context, Connection, string) (string, error)
	installRecovered bool
}
type Record = map[string]any

func value(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case json.Number:
		return string(n)
	}
	return ""
}
func write(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".mxioc-remote-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closed := f.Close()
	if err != nil {
		return err
	}
	if closed != nil {
		return closed
	}
	return os.Rename(f.Name(), path)
}
func Open(root string) (*Manager, error) {
	dir := filepath.Join(root, "remote")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "servers.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err == nil {
			_, err = f.Write([]byte(`{"servers":[],"jobs":[]}`))
			if err == nil {
				err = f.Sync()
			}
			closed := f.Close()
			if err != nil {
				return nil, err
			}
			if closed != nil {
				return nil, closed
			}
		} else if !os.IsExist(err) {
			return nil, err
		}
	}
	m := &Manager{root: dir, path: path}
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	keyFile := filepath.Join(dir, "credentials.key")
	m.key, err = os.ReadFile(keyFile)
	if os.IsNotExist(err) {
		if len(data["servers"].([]any)) != 0 {
			return nil, errors.New("凭据密钥缺失，请恢复原 credentials.key")
		}
		raw := make([]byte, 32)
		if _, err = rand.Read(raw); err != nil {
			return nil, err
		}
		encoded := []byte(base64.URLEncoding.EncodeToString(raw))
		f, createErr := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if createErr == nil {
			_, err = f.Write(encoded)
			if err == nil {
				err = f.Sync()
			}
			closed := f.Close()
			if err != nil {
				return nil, err
			}
			if closed != nil {
				return nil, closed
			}
		} else if !os.IsExist(createErr) {
			return nil, createErr
		}
		m.key, err = os.ReadFile(keyFile)
	}
	if err != nil {
		return nil, errors.New("凭据密钥读取失败")
	}
	decoded, err := base64.URLEncoding.DecodeString(string(m.key))
	if err != nil || len(decoded) != 32 {
		return nil, errors.New("凭据密钥格式无效")
	}
	return m, nil
}
func (m *Manager) load() (map[string]any, error) {
	raw, err := os.ReadFile(m.path)
	if err != nil {
		return nil, err
	}
	var data map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if decoder.Decode(&data) != nil || data == nil {
		return nil, errors.New("服务器索引损坏")
	}
	for _, key := range []string{"servers", "jobs"} {
		if data[key] == nil {
			data[key] = []any{}
		}
		if _, ok := data[key].([]any); !ok {
			return nil, errors.New("服务器索引格式无效")
		}
	}
	return data, nil
}
func (m *Manager) flush(data map[string]any) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return write(m.path, raw)
}
func find(data map[string]any, id string) (Record, error) {
	for _, v := range data["servers"].([]any) {
		record, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("服务器记录损坏")
		}
		if record["id"] == id {
			return record, nil
		}
	}
	return nil, errors.New("服务器不存在")
}
func (m *Manager) Record(id string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	return find(data, id)
}
func (m *Manager) Secret(record Record, key string) (string, error) {
	token := value(record[key])
	if token == "" {
		return "", errors.New("服务器凭据缺失")
	}
	plain, err := legacycrypto.DecryptFernet(m.key, token)
	if err != nil {
		return "", errors.New("服务器凭据解密失败，请检查 credentials.key")
	}
	return string(plain), nil
}
func publicServer(record Record) Record {
	result := Record{}
	for _, key := range []string{"id", "name", "host", "sshPort", "sshUser", "fingerprint", "domain", "nodeAddress", "panelUser", "panelAddress", "panelUrl", "panelPort", "panelPath", "panelTLS", "createdAt", "lastError", "connectionMode", "existingVerifiedAt", "certificateDomains", "installType"} {
		if v, ok := record[key]; ok {
			result[key] = v
		}
	}
	if result["installType"] == nil {
		result["installType"] = "3x-ui"
	}
	result["hasSSHPassword"] = value(record["sshPassword"]) != ""
	kind := value(result["installType"])
	result["hasPanelPassword"] = (kind == "3x-ui" || kind == "x-ui" || kind == "x-panel") && value(record["panelPassword"]) != ""
	result["hasCoreConfig"] = value(record["coreConfig"]) != ""
	return result
}
func (m *Manager) List() ([]Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	result := []Record{}
	for _, v := range data["servers"].([]any) {
		record, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("服务器记录损坏")
		}
		row := publicServer(record)
		for _, j := range data["jobs"].([]any) {
			job, ok := j.(map[string]any)
			if ok && job["serverId"] == record["id"] {
				filtered := Record{}
				for _, key := range []string{"id", "status", "stage", "error", "startedAt", "finishedAt"} {
					filtered[key] = job[key]
				}
				row["job"] = filtered
			}
		}
		result = append(result, row)
	}
	return result, nil
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func validHost(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return !ip.IsUnspecified() && !ip.IsMulticast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && !ip.IsLinkLocalMulticast()
	}
	return len(host) <= 253 && hostPattern.MatchString(host) && strings.Contains(host, ".") && !strings.Contains(host, "..")
}
func parsedPort(v any, defaultPort int) (int, error) {
	if v == nil || value(v) == "" {
		return defaultPort, nil
	}
	n, err := strconv.Atoi(value(v))
	if err != nil || n < 1 || n > 65535 {
		return 0, errors.New("端口必须在 1–65535 之间")
	}
	return n, nil
}
func serverHostKey(host string) string {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	return strings.ToLower(host)
}

func (m *Manager) sameRegistration(existing, submitted Record, panel bool) bool {
	for _, key := range []string{"name", "sshUser", "fingerprint", "installType", "connectionMode", "domain", "nodeAddress", "panelAddress"} {
		if value(existing[key]) != value(submitted[key]) {
			return false
		}
	}
	if panel && existing["panelUser"] != submitted["panelUser"] {
		return false
	}
	keys := []string{"sshPassword", "coreConfig"}
	if panel {
		keys = []string{"sshPassword", "panelPassword"}
	}
	for _, key := range keys {
		if value(existing[key]) == "" && value(submitted[key]) == "" {
			continue
		}
		old, oldErr := m.Secret(existing, key)
		next, nextErr := m.Secret(submitted, key)
		if oldErr != nil || nextErr != nil || subtle.ConstantTimeCompare([]byte(old), []byte(next)) != 1 {
			return false
		}
	}
	return true
}

func (m *Manager) Save(payload Record) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return nil, err
	}
	id := value(payload["id"])
	var record Record
	if id != "" {
		if operation := m.operations[id]; operation != nil && len(operation) > 0 {
			return nil, errors.New("服务器正在处理其他操作，请稍后修改")
		}
		record, err = find(data, id)
		if err != nil {
			return nil, err
		}
	} else {
		random := make([]byte, 12)
		if _, err = rand.Read(random); err != nil {
			return nil, err
		}
		id = hex.EncodeToString(random)
		record = Record{"id": id, "createdAt": time.Now().Unix(), "sshPort": 22, "sshUser": "root", "panelUser": "admin", "installType": "3x-ui", "connectionMode": "install"}
	}
	for _, value := range data["jobs"].([]any) {
		job, ok := value.(map[string]any)
		if ok && job["serverId"] == id && job["status"] == "running" {
			return nil, errors.New("安装任务进行中，不能修改服务器")
		}
	}
	previousKind := value(record["installType"])
	previousHost, previousFingerprint, previousSSHPort := value(record["host"]), value(record["fingerprint"]), value(record["sshPort"])
	if previousKind == "" {
		previousKind = "3x-ui"
	}
	for _, key := range []string{"name", "host", "sshUser", "fingerprint", "domain", "nodeAddress", "panelUser", "installType", "connectionMode"} {
		if v, ok := payload[key]; ok {
			if _, ok := v.(string); !ok {
				return nil, errors.New("服务器字段必须为字符串")
			}
			record[key] = v
		}
	}
	if strings.TrimSpace(value(record["name"])) == "" || len(value(record["name"])) > 300 {
		return nil, errors.New("服务器名称无效")
	}
	if !validHost(value(record["host"])) {
		return nil, errors.New("服务器 IP 或域名无效")
	}
	port, err := parsedPort(payload["sshPort"], 0)
	if payload["sshPort"] == nil {
		port, err = parsedPort(record["sshPort"], 22)
	}
	if err != nil {
		return nil, err
	}
	record["sshPort"] = port
	if port < 1 || port > 65535 {
		return nil, errors.New("SSH 端口无效")
	}
	if value(record["sshUser"]) == "" || len(value(record["sshUser"])) > 64 || strings.ContainsAny(value(record["sshUser"]), "\r\n\x00") {
		return nil, errors.New("SSH 用户名无效")
	}
	pin := strings.TrimPrefix(value(record["fingerprint"]), "SHA256:")
	decoded, err := base64.RawStdEncoding.DecodeString(pin)
	if !strings.HasPrefix(value(record["fingerprint"]), "SHA256:") || err != nil || len(decoded) != 32 {
		return nil, errors.New("请先检测并核对 SSH 主机指纹")
	}
	kind := value(record["installType"])
	panel := kind == "3x-ui" || kind == "x-ui" || kind == "x-panel"
	if !panel && kind != "xray" && kind != "sing-box" {
		return nil, errors.New("服务器内核类型无效")
	}
	if panel && (value(record["panelUser"]) == "" || len(value(record["panelUser"])) > 64 || strings.ContainsAny(value(record["panelUser"]), "\r\n\x00")) {
		return nil, errors.New("面板用户名无效")
	}
	mode := value(record["connectionMode"])
	if mode != "install" && mode != "existing" {
		return nil, errors.New("服务器接入模式无效")
	}
	if (kind == "x-ui" || kind == "x-panel") && mode != "existing" {
		return nil, errors.New("X-ui / X-Panel 仅支持接入现有面板")
	}
	if value(record["coreUserPending"]) != "" &&
		(kind != previousKind || value(record["host"]) != previousHost || value(record["fingerprint"]) != previousFingerprint ||
			strconv.Itoa(port) != previousSSHPort) {
		return nil, errors.New("独立内核用户变更待核对，暂不能更换服务器身份")
	}
	if kind != previousKind {
		for _, key := range []string{"panelAddress", "panelUrl", "panelPort", "panelPath", "panelTLS", "managed", "lastXrayBackup", "coreConfig", "coreState", "coreUserPending", "meters", "bandwidths", "relays"} {
			delete(record, key)
		}
	}

	if address, ok := payload["panelAddress"]; ok {
		text := value(address)
		if text == "" {
			delete(record, "panelAddress")
		} else {
			if !panel || mode != "existing" {
				return nil, errors.New("面板完整地址仅用于接入已安装面板")
			}
			u, err := url.Parse(text)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || !validHost(u.Hostname()) || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
				return nil, errors.New("面板地址无效")
			}
			panelPort := 443
			if u.Scheme == "http" {
				panelPort = 80
			}
			if u.Port() != "" {
				panelPort, err = strconv.Atoi(u.Port())
				if err != nil || panelPort < 1 || panelPort > 65535 {
					return nil, errors.New("面板端口无效")
				}
			}
			if !strings.HasSuffix(u.Path, "/") {
				u.Path += "/"
			}
			record["panelAddress"] = u.String()
			record["panelUrl"] = u.String()
			record["panelPort"] = panelPort
			record["panelPath"] = u.Path
			record["panelTLS"] = u.Scheme == "https"
		}
	}
	if !panel && value(record["domain"]) != "" {
		return nil, errors.New("独立内核的域名和 TLS 请在内核配置中设置")
	}
	if address := value(record["nodeAddress"]); address != "" && !validHost(address) {
		return nil, errors.New("节点访问地址无效")
	}
	if domain := value(record["domain"]); domain != "" && !hostPattern.MatchString(domain) {
		return nil, errors.New("面板域名无效")
	}
	if raw, ok := payload["coreConfig"]; ok && value(raw) != "" {
		if panel || mode == "existing" || len(value(raw)) > 128<<10 {
			return nil, errors.New("当前接入模式不接受安装配置")
		}
		var config map[string]any
		if json.Unmarshal([]byte(value(raw)), &config) != nil {
			return nil, errors.New("内核配置不是有效 JSON")
		}
		if _, ok := config["inbounds"].([]any); !ok {
			return nil, errors.New("内核配置缺少 inbounds")
		}
		if _, ok := config["outbounds"].([]any); !ok {
			return nil, errors.New("内核配置缺少 outbounds")
		}
		sealed, err := legacycrypto.EncryptFernet(m.key, []byte(value(raw)))
		if err != nil {
			return nil, err
		}
		record["coreConfig"] = sealed
	}
	if payload["clearCoreConfig"] == true {
		delete(record, "coreConfig")
	}
	for _, key := range []string{"sshPassword", "panelPassword"} {
		if key == "panelPassword" && !panel {
			delete(record, key)
			continue
		}
		if secret, ok := payload[key]; ok && value(secret) != "" {
			minimum := 1
			if key == "panelPassword" && mode != "existing" {
				minimum = 12
			}
			if len(value(secret)) < minimum || len(value(secret)) > 4096 {
				return nil, errors.New("密码长度无效")
			}
			record[key], err = legacycrypto.EncryptFernet(m.key, []byte(value(secret)))
			if err != nil {
				return nil, err
			}
		} else if value(record[key]) == "" {
			return nil, errors.New("请填写 SSH / 面板密码")
		}
	}
	var duplicate Record
	for _, item := range data["servers"].([]any) {
		other, ok := item.(Record)
		if !ok {
			return nil, errors.New("服务器记录损坏")
		}
		otherPort, portErr := parsedPort(other["sshPort"], 22)
		if other["id"] == id || portErr != nil || otherPort != port ||
			serverHostKey(value(other["host"])) != serverHostKey(value(record["host"])) {
			continue
		}
		if duplicate != nil {
			return nil, errors.New("该地址与 SSH 端口有多条登记，请检查服务器列表")
		}
		duplicate = other
	}
	if duplicate != nil {
		if value(payload["id"]) == "" && m.sameRegistration(duplicate, record, panel) {
			return publicServer(duplicate), nil
		}
		return nil, errors.New("该地址与 SSH 端口已登记，请在服务器列表编辑现有记录")
	}
	if value(payload["id"]) == "" {
		data["servers"] = append(data["servers"].([]any), record)
	}
	if err = m.flush(data); err != nil {
		return nil, err
	}
	return publicServer(record), nil
}
func (m *Manager) Connection(id string) (Connection, error) {
	record, err := m.Record(id)
	if err != nil {
		return Connection{}, err
	}
	return m.connectionRecord(record)
}
func (m *Manager) connectionRecord(record Record) (Connection, error) {
	password, err := m.Secret(record, "sshPassword")
	if err != nil {
		return Connection{}, err
	}
	port, err := parsedPort(record["sshPort"], 22)
	if err != nil {
		return Connection{}, err
	}
	return Connection{Host: value(record["host"]), Port: port, User: value(record["sshUser"]), Password: password, Fingerprint: value(record["fingerprint"])}, nil
}
