package remote

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
)

var runtimeBinaries = []string{"/usr/local/x-ui/bin/xray-linux-amd64", "/usr/local/x-ui/bin/xray-linux-arm64", "/usr/local/x-ui/bin/xray-linux-386", "/usr/local/x-ui/bin/xray", "/usr/local/bin/xray"}

func runtimeAddress(config Record) string {
	api, err := object(config["api"])
	if err != nil {
		return ""
	}
	if address := value(api["listen"]); address != "" {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return ""
		}
		ip := net.ParseIP(host)
		n, e := strconv.Atoi(port)
		if e != nil || n < 1 || n > 65535 || ip == nil || !ip.IsLoopback() {
			return ""
		}
		return net.JoinHostPort(host, strconv.Itoa(n))
	}
	tag := value(api["tag"])
	if tag == "" {
		tag = "api"
	}
	inbounds, _ := config["inbounds"].([]any)
	for _, v := range inbounds {
		row, err := object(v)
		if err != nil {
			return ""
		}
		if row["tag"] != tag {
			continue
		}
		port, err := strconv.Atoi(value(row["port"]))
		if err != nil || port < 1 || port > 65535 {
			return ""
		}
		host := value(row["listen"])
		if host == "" || host == "0.0.0.0" {
			host = "127.0.0.1"
		}
		if host == "::" {
			host = "::1"
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			return ""
		}
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return ""
}
func canonicalUUID(v any) (string, error) {
	s, ok := v.(string)
	if !ok {
		return "", errors.New("运行用户 UUID 格式无效")
	}
	s = strings.TrimPrefix(s, "urn:uuid:")
	s = strings.Trim(s, "{}")
	s = strings.ReplaceAll(s, "-", "")
	if len(s) != 32 {
		return "", errors.New("运行用户 UUID 格式无效")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return "", errors.New("运行用户 UUID 格式无效")
	}
	return hex.EncodeToString(b), nil
}
func runtimeStatus(output, protocol string, client Record) (string, error) {
	decoder := json.NewDecoder(strings.NewReader(output))
	decoder.UseNumber()
	var result Record
	if decoder.Decode(&result) != nil || result == nil {
		return "", errors.New("X-Panel 运行用户查询返回无效内容")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return "", errors.New("X-Panel 运行用户响应不完整或包含额外数据")
	}
	users, ok := result["users"].([]any)
	if !ok {
		return "", errors.New("X-Panel 运行用户列表格式无效")
	}
	matches := []Record{}
	for _, v := range users {
		user, err := object(v)
		if err != nil {
			return "", err
		}
		if user["email"] == client["email"] {
			matches = append(matches, user)
		}
	}
	if len(matches) == 0 {
		return "missing", nil
	}
	if len(matches) != 1 {
		return "mismatch", nil
	}
	account, err := object(matches[0]["account"])
	if err != nil {
		return "unsupported", nil
	}
	key := "id"
	if protocol == "trojan" {
		key = "password"
	}
	actual, present := account[key]
	if !present {
		return "unsupported", nil
	}
	if key == "id" {
		a, e := canonicalUUID(actual)
		if e != nil {
			return "", e
		}
		expected, e := canonicalUUID(client[key])
		if e != nil {
			return "", e
		}
		if a != expected {
			return "mismatch", nil
		}
	} else {
		a, ok := actual.(string)
		b, valid := client[key].(string)
		if !ok || !valid || b == "" {
			return "", errors.New("运行用户密码格式无效")
		}
		if a != b {
			return "mismatch", nil
		}
	}
	if protocol == "vless" {
		for _, record := range []Record{account, client} {
			if v, present := record["flow"]; present && v != nil {
				if _, ok := v.(string); !ok {
					return "", errors.New("运行用户 flow 格式无效")
				}
			}
		}
		a := strings.ReplaceAll(value(account["flow"]), "-udp443", "")
		b := strings.ReplaceAll(value(client["flow"]), "-udp443", "")
		if a != b {
			return "mismatch", nil
		}
	}
	return "present", nil
}
func runtimeNumber(v any) (int64, error) {
	if v == nil {
		return 0, nil
	}
	switch v.(type) {
	case int, int64, json.Number:
	default:
		return 0, errors.New("X-Panel 授权数值格式无效")
	}
	n, err := strconv.ParseInt(value(v), 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("X-Panel 授权数值范围无效")
	}
	return n, nil
}
func runtimeAuthorized(row, client Record, now time.Time) error {
	if row["enable"] == false || client["enable"] == false {
		return errors.New("X-Panel 入站或用户已停用，不自动恢复授权")
	}
	stats := Record{}
	count := 0
	if raw, present := row["clientStats"]; present && raw != nil {
		list, ok := raw.([]any)
		if !ok {
			return errors.New("X-Panel 用户流量记录格式无效")
		}
		for _, v := range list {
			s, err := object(v)
			if err != nil {
				return err
			}
			if s["email"] == client["email"] {
				stats = s
				count++
			}
		}
	}
	if count > 1 {
		return errors.New("X-Panel 用户流量记录重复，停止自动同步")
	}
	if stats["enable"] == false {
		return errors.New("X-Panel 用户授权已禁用，停止自动同步")
	}
	for _, item := range []Record{row, stats, client} {
		expire, err := runtimeNumber(item["expiryTime"])
		if err != nil {
			return err
		}
		if expire > 0 && expire <= now.UnixMilli() {
			return errors.New("X-Panel 远端授权已到期，不能补同步用户")
		}
	}
	for i, item := range []Record{row, stats} {
		total := item["total"]
		if total == nil && i == 1 {
			total = client["totalGB"]
		}
		limit, err := runtimeNumber(total)
		if err != nil {
			return err
		}
		up, err := runtimeNumber(item["up"])
		if err != nil {
			return err
		}
		down, err := runtimeNumber(item["down"])
		if err != nil {
			return err
		}
		used, err := billing.Add(up, down)
		if err != nil {
			return err
		}
		if limit > 0 && used >= limit {
			return errors.New("X-Panel 远端流量额度已用尽，不能补同步用户")
		}
	}
	return nil
}

// syncRuntime only adds a confirmed missing owned user. It never rewrites an
// inbound, removes a peer, resets counters or restarts a service.
func syncRuntime(ctx context.Context, panel *Panel, row, client Record) (Record, error) {
	unknown := Record{"runtimeVerified": nil}
	if err := runtimeAuthorized(row, client, time.Now()); err != nil {
		return nil, err
	}
	raw, err := panel.Request(ctx, "panel/api/server/getConfigJson", nil, "")
	if err != nil {
		var status panelStatus
		if errors.As(err, &status) && status.Code == 404 {
			return unknown, nil
		}
		return nil, err
	}
	if raw == nil {
		return unknown, nil
	}
	config, err := object(raw)
	if err != nil {
		return nil, errors.New("X-Panel 未返回有效内核配置")
	}
	address := runtimeAddress(config)
	protocol := value(row["protocol"])
	tag := value(row["tag"])
	email := value(client["email"])
	if address == "" || tag == "" || protocol != "vless" && protocol != "vmess" && protocol != "trojan" {
		return unknown, nil
	}
	if email == "" || len(email) > 1024 || len(tag) > 1024 || strings.ContainsAny(email+tag, "\x00\r\n") {
		return nil, errors.New("X-Panel 运行用户标签无效")
	}
	port, e := strconv.Atoi(value(row["port"]))
	if e != nil || port < 1 || port > 65535 {
		return nil, errors.New("X-Panel 入站端口无效")
	}
	if panel.run == nil {
		return nil, errors.New("X-Panel 运行核验 SSH 通道未初始化")
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	quoted := []string{}
	for _, path := range runtimeBinaries {
		quoted = append(quoted, quote(path))
	}
	discovery := "for candidate in " + strings.Join(quoted, " ") + `; do if [ -x "$candidate" ]; then printf '%s' "$candidate"; break; fi; done`
	output, err := panel.run(ctx, discovery, 4096)
	if err != nil {
		return nil, errors.New("X-Panel 内核程序探测失败")
	}
	binary := strings.TrimSpace(output)
	known := false
	for _, path := range runtimeBinaries {
		known = known || path == binary
	}
	if !known {
		return unknown, nil
	}
	query := quote(binary) + " api inbounduser --server=" + quote(address) + " -timeout=3 -tag=" + quote(tag) + " -email=" + quote(email)
	read := func() (string, error) {
		output, e := panel.run(ctx, query, 256<<10)
		if e != nil {
			lower := strings.ToLower(output)
			for _, marker := range []string{"unknown command", "unknown method", "unimplemented", "flag provided but not defined"} {
				if strings.Contains(lower, marker) {
					return "unsupported", nil
				}
			}
			return "", errors.New("无法连接 X-Panel 运行内核用户接口，身份记录已保留")
		}
		return runtimeStatus(output, protocol, client)
	}
	status, err := read()
	if err != nil {
		return nil, err
	}
	switch status {
	case "present":
		return Record{"runtimeVerified": true, "runtimeRepaired": false}, nil
	case "mismatch":
		return nil, errors.New("X-Panel 运行凭据与面板不一致，停止自动修复")
	case "unsupported":
		return unknown, nil
	case "missing":
	default:
		return nil, errors.New("X-Panel 运行用户状态无效")
	}
	settings, err := object(row["settings"])
	if err != nil {
		return nil, err
	}
	model := Record{}
	for key, v := range settings {
		if key != "clients" {
			model[key] = v
		}
	}
	owned := Record{}
	for key, v := range client {
		owned[key] = v
	}
	if protocol == "vless" && value(owned["flow"]) != "" {
		owned["flow"] = strings.ReplaceAll(value(owned["flow"]), "-udp443", "")
	}
	model["clients"] = []any{owned}
	payload := Record{"inbounds": []any{Record{"tag": tag, "listen": "127.0.0.1", "port": row["port"], "protocol": protocol, "settings": model}}}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	script := `set -eu
candidate=$(mktemp /tmp/mxioc-user-sync.XXXXXXXX)
trap 'rm -f "$candidate"' EXIT HUP INT TERM
chmod 600 "$candidate"
printf '%s' ` + quote(base64.StdEncoding.EncodeToString(encoded)) + ` | base64 -d > "$candidate"
` + quote(binary) + " api adu --server=" + quote(address) + " -timeout=3 \"$candidate\"\n"
	if _, err = panel.run(ctx, script, 256<<10); err != nil {
		return nil, errors.New("X-Panel 用户补同步结果待核对，请在同一入站重试")
	}
	status, err = read()
	if err != nil || status != "present" {
		return nil, errors.New("X-Panel 已保存用户，但运行内核尚未确认接收，请核对兼容性后重试")
	}
	return Record{"runtimeVerified": true, "runtimeRepaired": true}, nil
}
