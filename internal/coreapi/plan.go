package coreapi

import (
	"context"
	"errors"
	"strings"
)

type Plan struct {
	Action      string   `json:"action"`
	Previous    []byte   `json:"previous,omitempty"`
	Next        Record   `json:"next,omitempty"`
	Tag         string   `json:"tag,omitempty"`
	StatsReady  bool     `json:"statsReady,omitempty"`
	CancelKeys  []string `json:"cancelKeys,omitempty"`
	Certificate Record   `json:"certificate,omitempty"`
}

const XrayStatsReady = "ready=0\nfor attempt in 1 2 3 4 5; do\n" +
	" if timeout 2 /usr/local/bin/xray api statsquery --server=127.0.0.1:10085 --pattern='user>>>' >/dev/null 2>&1; then ready=1; break; fi\n" +
	" sleep 1\ndone\ntest \"$ready\" = 1"

// Execute is used only by a locally authorized Agent; fixed Xray paths
// and operations prevent remote callers from selecting an executable.
func Execute(ctx context.Context, p Plan, run func(context.Context, string, int) (string, error)) (string, error) {
	if run == nil {
		return "", errors.New("本机执行器缺失")
	}
	var script string
	limit := 64 << 10
	switch p.Action {
	case "read":
		script = "base64 < '/usr/local/etc/xray/config.json'"
		limit = 3 << 20
	case "tools":
		script = "test -x /usr/local/bin/xray"
	case "stats":
		script = "/usr/local/bin/xray api statsquery --server='127.0.0.1:10085' --pattern='user>>>'"
		limit = 2 << 20
	case "apply":
		if len(p.Previous) > 2<<20 || len(p.CancelKeys) > 1 {
			return "", errors.New("节点配置请求过大")
		}
		verify := ""
		if p.StatsReady {
			verify = XrayStatsReady
		}
		var err error
		script, err = WriteScript("xray", p.Previous, p.Next, p.Tag, verify, p.CancelKeys...)
		if err != nil {
			return "", err
		}
	case "certificate":
		for _, k := range []string{"certFile", "keyFile"} {
			v := value(p.Certificate[k])
			if !strings.HasPrefix(v, "/") || strings.ContainsAny(v, "\x00\r\n") {
				return "", errors.New("证书路径无效")
			}
		}

		if err := verifyCertificate(ctx, run, p.Certificate); err != nil {
			return "", err
		}
		return "MXIOC_CERTIFICATE_OK", nil
	default:
		return "", errors.New("不支持的本机内核 API 操作")
	}
	return run(ctx, script, limit)
}

func verifyCertificate(ctx context.Context, run func(context.Context, string, int) (string, error), payload Record) error {
	domain := value(payload["serverName"])
	if domain == "" || len(domain) > 253 || strings.ContainsAny(domain, "\x00\r\n") {
		return errors.New("证书域名无效")
	}
	script := "set -eu\ncert=" + quote(value(payload["certFile"])) + "\nkey=" + quote(value(payload["keyFile"])) + "\ndomain=" + quote(value(payload["serverName"])) + "\n" + `test -r "$cert" && test -r "$key"
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1
openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null 2>&1
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout)
key_pub=$(openssl pkey -in "$key" -passin pass: -pubout)
test "$cert_pub" = "$key_pub"
printf 'MXIOC_CERTIFICATE_OK\n'
`
	output, err := run(ctx, script, 16<<10)
	if err != nil || !strings.Contains(output, "MXIOC_CERTIFICATE_OK") {
		return errors.New("证书文件、有效期、域名或私钥匹配验证失败；请检查 OpenSSL 和证书路径，尚未创建节点")
	}
	return nil
}
