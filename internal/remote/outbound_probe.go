package remote

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"math"
	"strconv"
	"strings"
	"time"
)

var probeURLs = map[string]string{"gstatic": "https://www.gstatic.com/generate_204", "cloudflare": "https://cp.cloudflare.com/generate_204", "google": "https://www.google.com/generate_204"}

func outboundProbeScript(kind string, node Record, target string, native ...Record) (string, error) {
	url, ok := probeURLs[target]
	if !ok {
		return "", errors.New("请选择内置测试地址")
	}
	if node["dialer-proxy"] != nil {
		return "", errors.New("客户端代理链不能作为单个落地测试，请选择实际出口节点")
	}
	port, e := randomInboundPort()
	if e != nil {
		return "", e
	}
	secret := make([]byte, 24)
	if _, e = rand.Read(secret); e != nil {
		return "", e
	}
	password := hex.EncodeToString(secret)
	var doc Record
	var binary, flag string
	switch kind {
	case "xray":
		var out Record
		var e error
		if len(native) > 0 {
			out = native[0]
		} else {
			out, e = NodeOutbound(node, "tested-exit")
		}
		if e != nil {
			return "", e
		}
		doc = Record{"log": Record{"loglevel": "none"}, "inbounds": []any{Record{"listen": "127.0.0.1", "port": port, "protocol": "socks", "settings": Record{"auth": "password", "accounts": []any{Record{"user": "probe", "pass": password}}, "udp": false}}}, "outbounds": []any{out}}
		binary = "/usr/local/bin/xray"
		flag = "-config"
	case "sing-box":
		var out Record
		var e error
		if len(native) > 0 {
			out = native[0]
		} else {
			out, e = SingBoxOutbound(node, "tested-exit")
		}
		if e != nil {
			return "", e
		}
		doc = Record{"log": Record{"disabled": true}, "inbounds": []any{Record{"type": "socks", "listen": "127.0.0.1", "listen_port": port, "users": []any{Record{"username": "probe", "password": password}}}}, "outbounds": []any{out}}
		binary = "/usr/bin/sing-box"
		flag = "-c"
	default:
		return "", errors.New("出站测试需要独立 Xray 或 sing-box 服务器")
	}
	raw, e := json.Marshal(doc)
	if e != nil {
		return "", e
	}
	// A separate process owns a loopback-only authenticated SOCKS listener. There
	// is no freedom/direct fallback, no config write and no systemctl invocation.
	return `set -eu
umask 077
command -v curl >/dev/null && command -v timeout >/dev/null || { echo MXIOC_OUTBOUND_TOOLS; exit 0; }
test -x ` + quote(binary) + ` || { echo MXIOC_OUTBOUND_KERNEL; exit 0; }
work=$(mktemp -d /tmp/mxioc-outbound.XXXXXXXX)
pid=''
cleanup(){ test -z "$pid" || kill "$pid" 2>/dev/null || true; wait 2>/dev/null || true; rm -rf -- "$work"; }
trap cleanup EXIT
trap 'exit 130' HUP INT TERM
cat > "$work/probe.json" <<'MXIOC_OUTBOUND_CONFIG'
` + string(raw) + `
MXIOC_OUTBOUND_CONFIG
timeout 25 ` + quote(binary) + ` run ` + flag + ` "$work/probe.json" >/dev/null 2>&1 &
pid=$!
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 kill -0 "$pid" 2>/dev/null || { echo MXIOC_OUTBOUND_STARTUP; exit 0; }
 if timeout 1 bash -c ` + quote(fmt.Sprintf("true </dev/tcp/127.0.0.1/%d", port)) + ` 2>/dev/null; then ready=1; break; fi
 sleep .1
done
test "$ready" = 1 || { echo MXIOC_OUTBOUND_STARTUP; exit 0; }
set +e
result=$(curl --silent --output /dev/null --max-time 12 --connect-timeout 6 --noproxy '' --proxy ` + quote(fmt.Sprintf("socks5h://127.0.0.1:%d", port)) + ` --proxy-user ` + quote("probe:"+password) + ` --proto '=https' --write-out '%{http_code} %{time_total}' ` + quote(url) + ` 2>/dev/null)
rc=$?
set -e
printf 'MXIOC_OUTBOUND_RESULT %s %s\n' "$rc" "$result"
`, nil
}
func parseOutboundProbe(raw string) (Record, error) {
	result := Record{"ok": false, "milliseconds": nil}
	switch strings.TrimSpace(raw) {
	case "MXIOC_OUTBOUND_TOOLS":
		result["error"] = "服务器缺少 curl 或 timeout"
		return result, nil
	case "MXIOC_OUTBOUND_KERNEL":
		result["error"] = "服务器没有所选测试内核"
		return result, nil
	case "MXIOC_OUTBOUND_STARTUP":
		result["error"] = "隔离测试内核启动失败，请检查版本兼容性或端口冲突"
		return result, nil
	}
	f := strings.Fields(raw)
	if len(f) != 4 || f[0] != "MXIOC_OUTBOUND_RESULT" {
		return nil, errors.New("出站测试返回无效结果")
	}
	code, e := strconv.Atoi(f[1])
	if e != nil || code < 0 || code > 255 {
		return nil, errors.New("出站测试退出码无效")
	}
	status, e := strconv.Atoi(f[2])
	if e != nil || status < 0 || status > 599 {
		return nil, errors.New("出站测试状态码无效")
	}
	elapsed, e := strconv.ParseFloat(f[3], 64)
	if e != nil || math.IsNaN(elapsed) || math.IsInf(elapsed, 0) || elapsed < 0 || elapsed > 20 {
		return nil, errors.New("出站测试耗时无效")
	}
	result["httpStatus"], result["curlCode"] = status, code
	if code == 0 && status == 204 {
		result["ok"] = true
		result["milliseconds"] = math.Round(elapsed*10000) / 10
	} else {
		reasons := map[int]string{5: "代理地址解析失败", 6: "测试域名解析失败", 7: "代理入口连接失败", 28: "代理握手或请求超时", 35: "TLS 握手失败", 60: "测试站点证书校验失败", 97: "代理认证或握手失败"}
		result["error"] = reasons[code]
		if result["error"] == "" {
			result["error"] = "测试地址未通过代理返回 HTTP 204"
		}
	}
	return result, nil
}
func (m *Manager) ProbeOutbound(ctx context.Context, id, link, target string) (Record, error) {
	node, e := links.Parse(link)
	if e != nil {
		return nil, errors.New("落地分享链接无效或协议不支持")
	}
	row, e := m.Record(id)
	if e != nil {
		return nil, e
	}
	script, e := outboundProbeScript(value(row["installType"]), node, target)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	connection, e := m.connectionRecord(row)
	if e != nil {
		return nil, e
	}
	raw, e := Execute(ctx, connection, script, 4096)
	if e != nil {
		return nil, errors.New("出站测试执行失败或已取消；未修改业务配置")
	}
	latest, e := m.Record(id)
	if e != nil || certificateRevision(latest) != certificateRevision(row) {
		return nil, errors.New("测试期间服务器身份变化，结果已丢弃")
	}
	result, e := parseOutboundProbe(raw)
	if e != nil {
		return nil, e
	}
	result["target"], result["serverName"], result["time"] = target, row["name"], time.Now().Unix()
	return result, nil
}

// Exposes only tag/protocol for administrator selection, never outbound secrets.
func (m *Manager) OutboundProbeTargets(ctx context.Context, id string) (Record, error) {
	result, e := m.CoreConfig(ctx, id, "", nil)
	if e != nil {
		return nil, e
	}
	doc, _ := result["config"].(Record)
	targets := []Record{}
	for _, out := range anyRecords(doc["outbounds"]) {
		tag := value(out["tag"])
		if tag == "" {
			continue
		}
		kind := value(out["protocol"])
		if kind == "" {
			kind = value(out["type"])
		}
		targets = append(targets, Record{"tag": tag, "protocol": kind})
	}
	return Record{"outbounds": targets}, nil
}
func (m *Manager) ProbeConfiguredOutbound(ctx context.Context, id, tag, target string) (Record, error) {
	if tag == "" || len(tag) > 256 {
		return nil, errors.New("出站标签无效")
	}
	row, e := m.Record(id)
	if e != nil {
		return nil, e
	}
	result, e := m.CoreConfig(ctx, id, "", nil)
	if e != nil {
		return nil, e
	}
	doc, _ := result["config"].(Record)
	var selected Record
	for _, out := range anyRecords(doc["outbounds"]) {
		if out["tag"] == tag {
			if selected != nil {
				return nil, errors.New("出站标签重复")
			}
			selected = out
		}
	}
	if selected == nil {
		return nil, errors.New("所选出站已不存在")
	}
	stream, _ := selected["streamSettings"].(Record)
	sock, _ := stream["sockopt"].(Record)
	if selected["proxySettings"] != nil || selected["detour"] != nil || sock["dialerProxy"] != nil || selected["outbounds"] != nil {
		return nil, errors.New("此出站引用其他出站，暂不支持独立测试")
	}
	script, e := outboundProbeScript(value(row["installType"]), Record{}, target, selected)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	connection, e := m.connectionRecord(row)
	if e != nil {
		return nil, e
	}
	raw, e := Execute(ctx, connection, script, 4096)
	if e != nil {
		return nil, errors.New("出站测试执行失败或已取消，未修改业务配置")
	}
	latest, e := m.Record(id)
	if e != nil || certificateRevision(latest) != certificateRevision(row) {
		return nil, errors.New("服务器身份已变化")
	}
	result, e = parseOutboundProbe(raw)
	if e == nil {
		result["tag"], result["target"], result["serverName"] = tag, target, row["name"]
	}
	return result, e
}
