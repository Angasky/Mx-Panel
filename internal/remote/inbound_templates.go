package remote

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"net/netip"
	"path"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
)

func randomInboundPort() (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(45535))
	if err != nil {
		return 0, err
	}
	return 20001 + int(n.Int64()), nil
}

func templateName(payload Record) string {
	if name := value(payload["template"]); name != "" {
		return name
	}
	return "vless-reality"
}
func tlsTemplate(name string) bool {
	return name == "trojan-tls" || name == "vless-ws-tls" || name == "hysteria2"
}

// Templates start without authentication users. The subscription controller
// persists ownership before granting the first usable UUID/password.
func buildInboundTemplate(payload Record, address string) (Record, error) {
	if payload["inbound"] != nil {
		return nil, errors.New("原始入站新增尚未适配，请使用节点模板")
	}
	name := templateName(payload)
	if name != "vless-reality" && name != "vmess-tcp" && !tlsTemplate(name) {
		return nil, errors.New("此模板尚未适配已有面板的独立用户创建")
	}
	port, err := parsedPort(payload["port"], 0)
	if payload["port"] == nil || payload["port"] == "" {
		port, err = randomInboundPort()
	}
	if err != nil || port < 1 {
		return nil, errors.New("监听端口必须为 1–65535")
	}
	remark := strings.TrimSpace(value(payload["remark"]))
	if remark == "" {
		remark = "新建节点"
	}
	if len([]rune(remark)) > 100 || strings.ContainsAny(remark, "\x00\r\n") {
		return nil, errors.New("节点名称必须为 1–100 个字符")
	}
	clients := []any{}
	settings := Record{"clients": clients}
	stream := Record{"network": "tcp", "security": "none", "tcpSettings": Record{"header": Record{"type": "none"}}}
	protocol := "vless"
	switch name {
	case "vless-reality":
		domain, err := certificateDomain(value(payload["serverName"]))
		if err != nil {
			return nil, errors.New("Reality 需要有效的伪装域名")
		}
		if address == "" {
			return nil, errors.New("请先完成此服务器的 SNI 实测")
		}
		ip, e := netip.ParseAddr(address)
		if e != nil || !netguard.PublicAddress(ip) {
			return nil, errors.New("Reality 实测地址必须为公网 IP")
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		short := make([]byte, 8)
		if _, err = rand.Read(short); err != nil {
			return nil, err
		}
		stream["security"] = "reality"
		stream["realitySettings"] = Record{"show": false, "xver": 0, "target": net.JoinHostPort(address, "443"), "serverNames": []any{domain}, "privateKey": base64.RawURLEncoding.EncodeToString(private.Bytes()), "shortIds": []any{hex.EncodeToString(short)}, "settings": Record{"publicKey": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "fingerprint": "chrome", "serverName": domain, "spiderX": "/"}}
		settings["decryption"] = "none"
		settings["fallbacks"] = []any{}
	case "vmess-tcp":
		protocol = "vmess"
		settings["disableInsecureEncryption"] = false
	default:
		domain, err := certificateDomain(value(payload["serverName"]))
		if err != nil {
			return nil, err
		}
		cert, key := value(payload["certFile"]), value(payload["keyFile"])
		for _, p := range []string{cert, key} {
			if !strings.HasPrefix(p, "/") || path.Clean(p) != p || len(p) > 512 || strings.ContainsAny(p, "\x00\r\n") {
				return nil, errors.New("证书和私钥必须填写远端绝对文件路径")
			}
		}
		alpn := []any{"h2", "http/1.1"}
		if name == "trojan-tls" {
			protocol = "trojan"
		} else if name == "hysteria2" {
			protocol = "hysteria"
			settings["version"] = 2
			stream["network"] = "hysteria"
			stream["hysteriaSettings"] = Record{"version": 2}
			alpn = []any{"h3"}
		} else {
			settings["decryption"] = "none"
			ws := value(payload["path"])
			if ws == "" {
				ws = "/"
			}
			if len(ws) > 256 || !strings.HasPrefix(ws, "/") || strings.ContainsAny(ws, "\x00\r\n") {
				return nil, errors.New("WebSocket 路径必须以 / 开头且不超过 256 字节")
			}
			stream["network"] = "ws"
			stream["wsSettings"] = Record{"path": ws}
		}
		stream["security"] = "tls"
		stream["tlsSettings"] = Record{"serverName": domain, "alpn": alpn, "certificates": []any{Record{"certificateFile": cert, "keyFile": key}}}
	}
	return Record{"remark": remark, "port": port, "protocol": protocol, "enable": true, "listen": "", "up": 0, "down": 0, "total": 0, "expiryTime": 0, "settings": settings, "streamSettings": stream, "sniffing": Record{"enabled": true, "destOverride": []any{"http", "tls", "quic"}}}, nil
}

func (m *Manager) templatePayload(server string, record, payload Record) (Record, string, error) {
	prepared := Record{}
	for k, v := range payload {
		prepared[k] = v
	}
	name := templateName(prepared)
	if tlsTemplate(name) && prepared["certificateMode"] == "auto" {
		job, err := m.ReadyCertificate(server, value(prepared["certificateJobId"]), value(prepared["serverName"]))
		if err != nil {
			return nil, "", err
		}
		for k, v := range job {
			prepared[k] = v
		}
	}
	if tlsTemplate(name) && value(prepared["certificateMode"]) != "" && prepared["certificateMode"] != "auto" && prepared["certificateMode"] != "manual" {
		return nil, "", errors.New("证书方式必须为自动或手动")
	}
	if name != "vless-reality" {
		return prepared, "", nil
	}
	domain, err := certificateDomain(value(prepared["serverName"]))
	if err != nil {
		return nil, "", err
	}
	scanner := m.sniState()
	revision := certificateRevision(record)
	scanner.mu.Lock()
	defer scanner.mu.Unlock()
	address := ""
	var newest int64
	for key, entry := range scanner.cache {
		age := scanner.now().Sub(entry.at)
		if key.server == server && key.revision == revision && key.domain == domain && entry.ok && age >= 0 && age.Minutes() < 10 && (value(prepared["sniAddress"]) == "" || value(prepared["sniAddress"]) == key.address) {
			if address == "" || entry.at.UnixNano() > newest {
				address = key.address
				newest = entry.at.UnixNano()
			}
		}
	}
	if address == "" {
		return nil, "", errors.New("SNI 实测结果缺失或已过期，请扫描并选择通过的域名")
	}
	return prepared, address, nil
}

func validateTemplateCertificate(ctx context.Context, panel *Panel, payload Record) error {
	if !tlsTemplate(templateName(payload)) {
		return nil
	}
	if panel.run == nil {
		return errors.New("证书验证通道未就绪，尚未创建节点")
	}
	script := "set -eu\ncert=" + quote(value(payload["certFile"])) + "\nkey=" + quote(value(payload["keyFile"])) + "\ndomain=" + quote(value(payload["serverName"])) + "\n" + `test -r "$cert" && test -r "$key"
openssl x509 -in "$cert" -noout -checkend 0 >/dev/null 2>&1
openssl x509 -in "$cert" -noout -checkhost "$domain" >/dev/null 2>&1
cert_pub=$(openssl x509 -in "$cert" -pubkey -noout)
key_pub=$(openssl pkey -in "$key" -passin pass: -pubout)
test "$cert_pub" = "$key_pub"
printf 'MXIOC_CERTIFICATE_OK\n'
`
	output, err := panel.run(ctx, script, 16<<10)
	if err != nil || !strings.Contains(output, "MXIOC_CERTIFICATE_OK") {
		return errors.New("证书文件、有效期、域名或私钥匹配验证失败；请检查 OpenSSL 和证书路径，尚未创建节点")
	}
	return nil
}
