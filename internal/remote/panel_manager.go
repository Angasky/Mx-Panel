package remote

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type cachedPanel struct {
	identity [32]byte
	state    *PanelSession
	used     time.Time
}

var ansiPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var portSetting = regexp.MustCompile(`(?m)^port(?:（[^\n]*?）)?:[ \t]*(\d+)[ \t]*$`)
var pathSetting = regexp.MustCompile(`(?m)^webBasePath(?:（[^\n]*?）)?:[ \t]*(\S+)[ \t]*$`)
var certSetting = regexp.MustCompile(`(?m)^cert:[ \t]*(\S+)[ \t]*$`)
var tokenSetting = regexp.MustCompile(`(?m)^apiToken:[ \t]*(\S+)`)
var basePathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9_.~-]+/)*$`)

func parsePanelSettings(output string, record Record) (Record, error) {
	output = ansiPattern.ReplaceAllString(output, "")
	portMatch := portSetting.FindStringSubmatch(output)
	pathMatch := pathSetting.FindStringSubmatch(output)
	if len(portMatch) < 2 || len(pathMatch) < 2 {
		return nil, errors.New("无法读取面板端口或路径，请填写现有面板完整地址")
	}
	port, err := strconv.Atoi(portMatch[1])
	if err != nil || port < 1 || port > 65535 {
		return nil, errors.New("面板端口无效")
	}
	path := "/" + strings.Trim(pathMatch[1], "/")
	if path != "/" {
		path += "/"
	}
	if !basePathPattern.MatchString(path) || strings.Contains(path, "..") {
		return nil, errors.New("面板路径无效")
	}
	cert := certSetting.FindStringSubmatch(output)
	secure := len(cert) > 1 && cert[1] != "<nil>" && cert[1] != "null" && cert[1] != ""
	host := value(record["host"])
	if secure && value(record["domain"]) != "" {
		host = value(record["domain"])
	}
	scheme := "http"
	if secure {
		scheme = "https"
	}
	address := url.URL{Scheme: scheme, Host: net.JoinHostPort(host, strconv.Itoa(port)), Path: path}
	return Record{"panelPort": port, "panelPath": path, "panelTLS": secure, "panelUrl": address.String()}, nil
}
func (m *Manager) updateDerived(id string, updates Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	record, err := find(data, id)
	if err != nil {
		return err
	}
	for key, v := range updates {
		switch key {
		case "panelUrl", "panelPort", "panelPath", "panelTLS", "existingVerifiedAt", "lastError":
			record[key] = v
		default:
			return errors.New("不支持的派生字段")
		}
	}
	return m.flush(data)
}
func (m *Manager) WithPanel(ctx context.Context, id string, action func(*Panel, Record) (any, error)) (any, error) {
	m.mu.Lock()
	data, err := m.load()
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	record, err := find(data, id)
	if err != nil {
		m.mu.Unlock()
		return nil, err
	}
	kind := value(record["installType"])
	if kind == "" {
		kind = "3x-ui"
	}
	if kind != "3x-ui" && kind != "x-ui" && kind != "x-panel" {
		m.mu.Unlock()
		return nil, errors.New("该服务器不是 Web 面板，需使用原生内核适配")
	}
	for _, value := range data["jobs"].([]any) {
		job, ok := value.(map[string]any)
		if ok && job["serverId"] == id && job["status"] == "running" {
			m.mu.Unlock()
			return nil, errors.New("请等待服务器安装任务完成")
		}
	}
	if m.operations == nil {
		m.operations = map[string]chan struct{}{}
	}
	operation := m.operations[id]
	if operation == nil {
		operation = make(chan struct{}, 1)
		m.operations[id] = operation
	}
	select {
	case operation <- struct{}{}:
	default:
		m.mu.Unlock()
		return nil, errors.New("该服务器正在处理其他操作，请稍后重试")
	}
	m.mu.Unlock()
	defer func() { <-operation }()
	connection, err := m.Connection(id)
	if err != nil {
		return nil, err
	}
	client, err := Connect(ctx, connection)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	endpoint := value(record["panelAddress"])
	if endpoint == "" {
		endpoint = value(record["panelUrl"])
	}
	if endpoint == "" {
		if kind == "x-panel" {
			return nil, errors.New("X-Panel 请填写现有面板完整地址，避免运行会迁移数据库的 CLI")
		}
		output, err := executeClient(ctx, client, connection, "cd /usr/local/x-ui && ./x-ui setting -show true && { ./x-ui setting -getCert true 2>/dev/null || true; }", 256<<10)
		if err != nil {
			return nil, errors.New("面板设置读取失败，请核对安装路径或填写完整面板地址")
		}
		settings, err := parsePanelSettings(output, record)
		if err != nil {
			return nil, err
		}
		if err = m.updateDerived(id, settings); err != nil {
			return nil, err
		}
		for key, v := range settings {
			record[key] = v
		}
	}
	token := ""
	if kind != "x-panel" {
		output, tokenErr := executeClient(ctx, client, connection, "cd /usr/local/x-ui && ./x-ui setting -getApiToken true", 64<<10)
		if tokenErr == nil {
			if matches := tokenSetting.FindStringSubmatch(output); len(matches) > 1 {
				token = matches[1]
			}
		}
		if token == "" && record["connectionMode"] != "existing" {
			return nil, errors.New("面板未返回 API 令牌，请核对指定 3x-ui 分支")
		}
	}
	password, err := m.Secret(record, "panelPassword")
	if err != nil {
		return nil, err
	}
	binding := []any{record["host"], record["sshPort"], record["sshUser"], record["sshPassword"], record["fingerprint"], record["panelUser"], record["panelPassword"], record["panelAddress"], record["panelUrl"], token}
	encoded, _ := json.Marshal(binding)
	identity := sha256.Sum256(encoded)
	m.mu.Lock()
	if m.panels == nil {
		m.panels = map[string]*cachedPanel{}
	}
	cached := m.panels[id]
	if cached == nil || cached.identity != identity {
		cached = &cachedPanel{identity: identity, state: NewPanelSession()}
		m.panels[id] = cached
	}
	cached.used = time.Now()
	if len(m.panels) > 1024 {
		oldestID := ""
		var oldest time.Time
		for key, p := range m.panels {
			if key != id && (oldest.IsZero() || p.used.Before(oldest)) {
				oldestID = key
				oldest = p.used
			}
		}
		if oldestID != "" {
			delete(m.panels, oldestID)
		}
	}
	m.mu.Unlock()
	panel, err := NewPinnedPanel(client, record, password, token, cached.state)
	if err != nil {
		return nil, err
	}
	panel.run = func(ctx context.Context, script string, limit int) (string, error) {
		return executeClient(ctx, client, connection, script, limit)
	}
	return action(panel, record)
}
func (m *Manager) AttachPanel(ctx context.Context, id string) (Record, error) {
	_, err := m.WithPanel(ctx, id, func(panel *Panel, record Record) (any, error) {
		if _, err := panel.Request(ctx, "login", nil, ""); err != nil {
			return nil, err
		}
		return panel.Request(ctx, "panel/api/inbounds/list", nil, "")
	})
	if err != nil {
		return nil, err
	}
	if err = m.updateDerived(id, Record{"existingVerifiedAt": time.Now().Unix(), "lastError": ""}); err != nil {
		return nil, err
	}
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	return Record{"server": publicServer(record), "message": "已有面板登录和 API 验证成功"}, nil
}
