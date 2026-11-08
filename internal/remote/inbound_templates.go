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
	"regexp"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/links"
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
	return tcpTLSTemplate(name) || wsTemplate(name) || name == "vless-xhttp-tls" || grpcTemplate(name) || name == "hysteria2" || name == "tuic"
}

func tcpTLSTemplate(name string) bool {
	return name == "vless-tcp-tls" || name == "vmess-tcp-tls" || name == "trojan-tls"
}

func wsTemplate(name string) bool {
	return name == "vless-ws-tls" || name == "vmess-ws-tls" || name == "trojan-ws-tls"
}

func grpcTemplate(name string) bool {
	return name == "vless-grpc-tls" || name == "vmess-grpc-tls" || name == "trojan-grpc-tls"
}

var grpcServiceName = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

// Templates start without authentication users. The subscription controller
// persists ownership before granting the first usable UUID/password.
func buildInboundTemplate(payload Record, address string) (Record, error) {
	if payload["inbound"] != nil {
		return nil, errors.New("原始入站新增尚未适配，请使用节点模板")
	}
	name := templateName(payload)
	if _, exists := payload["alpn"]; exists && !tlsTemplate(name) {
		return nil, errors.New("该模板不支持 TLS ALPN")
	}
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
		} else if tcpTLSTemplate(name) {
			if name == "vmess-tcp-tls" {
				protocol = "vmess"
				settings["disableInsecureEncryption"] = false
			} else {
				settings["decryption"] = "none"
			}
		} else if name == "hysteria2" {
			protocol = "hysteria"
			settings["version"] = 2
			stream["network"] = "hysteria"
			stream["hysteriaSettings"] = Record{"version": 2}
			alpn = []any{"h3"}
		} else if name == "tuic" {
			protocol = "tuic"
			alpn = nil // Use the core's TUIC ALPN default.
		} else if name == "vless-xhttp-tls" {
			options := Record{"path": "/vpn", "mode": "stream-up"}
			for field, key := range map[string]string{"path": "path", "xhttpMode": "mode", "xhttpHost": "host"} {
				if v, exists := payload[field]; exists {
					options[key] = v
				}
			}
			options, err := links.XHTTPOptions(options)
			if err != nil {
				return nil, errors.New("XHTTP 路径或传输模式无效")
			}
			settings["decryption"] = "none"
			stream["network"], stream["xhttpSettings"] = "xhttp", options
			alpn = []any{"h2"}
		} else if grpcTemplate(name) {
			service := "vpn"
			if raw, exists := payload["grpcService"]; exists {
				var ok bool
				service, ok = raw.(string)
				if !ok || !grpcServiceName.MatchString(service) {
					return nil, errors.New("gRPC 服务名须为 1–128 个字母、数字、点、下划线或连字符")
				}
			}
			if name == "vmess-grpc-tls" {
				protocol = "vmess"
				settings["disableInsecureEncryption"] = false
			} else if name == "trojan-grpc-tls" {
				protocol = "trojan"
			} else {
				settings["decryption"] = "none"
			}
			stream["network"] = "grpc"
			stream["grpcSettings"] = Record{"serviceName": service}
			alpn = []any{"h2"}
		} else {
			if name == "vmess-ws-tls" {
				protocol = "vmess"
				settings["disableInsecureEncryption"] = false
			} else if name == "trojan-ws-tls" {
				protocol = "trojan"
			} else {
				settings["decryption"] = "none"
			}
			ws := "/"
			if raw, exists := payload["path"]; exists {
				var ok bool
				ws, ok = raw.(string)
				if !ok {
					return nil, errors.New("WebSocket 路径必须为字符串")
				}
				if ws == "" {
					ws = "/"
				}
			}
			stream["network"] = "ws"
			stream["wsSettings"] = Record{"path": "/"}
			// Reuse the editor's validation so newly created paths and Host
			// can be edited and shared without silently changing their meaning.
			patch := Record{"wsPath": ws}
			if host, exists := payload["wsHost"]; exists {
				patch["wsHost"] = host
			}
			candidate, err := prepareManagedCoreEdit(Record{"streamSettings": stream}, patch)
			if err != nil {
				return nil, err
			}
			stream = candidate["streamSettings"].(Record)
		}
		stream["security"] = "tls"
		tls := Record{"serverName": domain, "certificates": []any{Record{"certificateFile": cert, "keyFile": key}}}
		if alpn != nil {
			tls["alpn"] = alpn
		}
		stream["tlsSettings"] = tls
		if raw, exists := payload["alpn"]; exists {
			if !tcpTLSTemplate(name) && !wsTemplate(name) && !grpcTemplate(name) && name != "vless-xhttp-tls" {
				return nil, errors.New("该模板暂不支持自定义 ALPN")
			}
			text, ok := raw.(string)
			if !ok {
				return nil, errors.New("ALPN 必须为逗号分隔的字符串")
			}
			alpn, err := parseManagedALPN(text, value(stream["network"]))
			if err != nil {
				return nil, err
			}
			if alpn == nil {
				delete(tls, "alpn")
			} else {
				tls["alpn"] = alpn
			}
		}
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
	return verifyTemplateCertificate(ctx, panel.run, payload)
}

func verifyTemplateCertificate(ctx context.Context, run coreRunner, payload Record) error {
	if run == nil {
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
	output, err := run(ctx, script, 16<<10)
	if err != nil || !strings.Contains(output, "MXIOC_CERTIFICATE_OK") {
		return errors.New("证书文件、有效期、域名或私钥匹配验证失败；请检查 OpenSSL 和证书路径，尚未创建节点")
	}
	return nil
}
