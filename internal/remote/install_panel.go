package remote

import (
	"context"
	_ "embed"
	"errors"
	"strings"
)

//go:embed scripts/install-panel.sh
var installPanel string

func panelInstallScript(record Record, password string) (string, error) {
	if value(record["installType"]) != "3x-ui" {
		return "", errors.New("只有指定 3x-ui 分支支持自动安装；其他面板请接入已有软件")
	}
	user := value(record["panelUser"])
	if user == "" || password == "" || strings.ContainsAny(user+password, "\x00\r\n") {
		return "", errors.New("请先设置有效的面板账号和密码")
	}
	env := "XUI_AUTO=1"
	if value(record["domain"]) != "" {
		domain, err := certificateDomain(value(record["domain"]))
		if err != nil {
			return "", err
		}
		env = "XUI_DOMAIN=" + quote(domain)
	}
	return strings.NewReplacer("__MXIOC_ENV__", env, "__MXIOC_USER__", quote(user), "__MXIOC_PASSWORD__", quote(password)).Replace(strings.ReplaceAll(installPanel, "\r\n", "\n")), nil
}

func (m *Manager) verifyInstalledPanel(ctx context.Context, id string) (string, error) {
	record, err := m.Record(id)
	if err != nil {
		return "", err
	}
	connection, err := m.connectionRecord(record)
	if err != nil {
		return "", err
	}
	client, err := Connect(ctx, connection)
	if err != nil {
		return "", err
	}
	defer client.Close()
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			client.Close()
		case <-done:
		}
	}()
	output, err := executeClient(ctx, client, connection, "cd /usr/local/x-ui && ./x-ui setting -show true && { ./x-ui setting -getCert true 2>/dev/null || true; }", 256<<10)
	if err != nil {
		return "", errors.New("安装结束，面板设置读取失败")
	}
	settings, err := parsePanelSettings(output, record)
	if err != nil {
		return "", err
	}
	if value(record["domain"]) != "" && settings["panelTLS"] != true {
		return "", errors.New("面板已安装但域名 HTTPS 未就绪，请检查解析和证书日志")
	}
	for k, v := range settings {
		record[k] = v
	}
	output, err = executeClient(ctx, client, connection, "cd /usr/local/x-ui && ./x-ui setting -getApiToken true", 64<<10)
	if err != nil {
		return "", errors.New("安装结束，API 令牌读取失败")
	}
	matches := tokenSetting.FindStringSubmatch(output)
	if len(matches) < 2 {
		return "", errors.New("安装结束，未读取到 API 令牌")
	}
	password, err := m.Secret(record, "panelPassword")
	if err != nil {
		return "", err
	}
	panel, err := NewPinnedPanel(client, record, password, matches[1], NewPanelSession())
	if err != nil {
		return "", err
	}
	// Explicit login proves the configured credentials, not merely API token access.
	if _, err = panel.Request(ctx, "login", nil, ""); err != nil {
		return "", err
	}
	if _, err = panel.Request(ctx, "panel/api/inbounds/list", nil, ""); err != nil {
		return "", err
	}
	if err = m.updateDerived(id, settings); err != nil {
		return "", err
	}
	return value(settings["panelUrl"]), nil
}
