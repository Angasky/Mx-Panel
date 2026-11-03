package remote

import (
	"context"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func object(v any) (Record, error) {
	if v == nil {
		return Record{}, nil
	}
	if record, ok := v.(map[string]any); ok {
		return record, nil
	}
	if text, ok := v.(string); ok {
		decoder := json.NewDecoder(strings.NewReader(text))
		decoder.UseNumber()
		var result Record
		if decoder.Decode(&result) == nil && result != nil {
			return result, nil
		}
	}
	return nil, errors.New("远端入站 JSON 配置无效")
}
func nodeAddress(record Record) string {
	for _, key := range []string{"nodeAddress", "domain", "host"} {
		if v := value(record[key]); v != "" {
			return v
		}
	}
	return ""
}
func InboundNodes(row, record Record) ([]Record, error) {
	settings, err := object(row["settings"])
	if err != nil {
		return nil, err
	}
	stream, err := object(row["streamSettings"])
	if err != nil {
		return nil, err
	}
	protocol := value(row["protocol"])
	if protocol == "hysteria" || protocol == "hy2" {
		if v := value(settings["version"]); v != "" && v != "2" {
			return []Record{}, nil
		}
		protocol = "hysteria2"
	}
	name := value(row["remark"])
	if name == "" {
		name = "服务器节点"
	}
	makeNode := func() Record {
		return Record{"name": name, "type": protocol, "server": nodeAddress(record), "port": row["port"]}
	}
	if protocol == "socks" || protocol == "http" {
		accounts, _ := settings["accounts"].([]any)
		if len(accounts) == 0 {
			accounts = []any{Record{}}
		}
		result := []Record{}
		for _, v := range accounts {
			account, err := object(v)
			if err != nil {
				return nil, err
			}
			node := makeNode()
			if protocol == "socks" {
				node["type"] = "socks5"
			}
			if value(account["user"]) != "" || value(account["pass"]) != "" {
				node["username"] = account["user"]
				node["password"] = account["pass"]
			}
			result = append(result, node)
		}
		return result, nil
	}
	if protocol == "shadowsocks" {
		if value(settings["password"]) == "" || value(settings["method"]) == "" {
			return []Record{}, nil
		}
		node := makeNode()
		node["type"] = "ss"
		node["cipher"] = settings["method"]
		node["password"] = settings["password"]
		return []Record{node}, nil
	}
	if protocol != "vless" && protocol != "vmess" && protocol != "trojan" && protocol != "hysteria2" && protocol != "tuic" {
		return []Record{}, nil
	}
	clients, _ := settings["clients"].([]any)
	if clients == nil {
		clients, _ = settings["users"].([]any)
	}
	result := []Record{}
	for _, v := range clients {
		client, err := object(v)
		if err != nil {
			return nil, err
		}
		if client["enable"] == false {
			continue
		}
		node := makeNode()
		if len(clients) > 1 {
			node["name"] = name + " / " + value(client["email"])
		}
		switch protocol {
		case "trojan":
			node["password"] = client["password"]
		case "hysteria2":
			password := value(client["auth"])
			if password == "" {
				password = value(client["password"])
			}
			if password == "" {
				return nil, errors.New("HY2 用户缺少 auth 密码")
			}
			node["password"] = password
			node["udp"] = true
		default:
			node["uuid"] = client["id"]
		}
		if protocol == "tuic" {
			node["password"] = client["password"]
		}
		if protocol == "vmess" {
			node["cipher"] = "auto"
			node["alterId"] = 0
		}
		if value(client["flow"]) != "" {
			node["flow"] = client["flow"]
		}
		network := value(stream["network"])
		if network != "" && network != "tcp" && network != "raw" && protocol != "hysteria2" {
			node["network"] = network
		}
		if network == "ws" {
			ws, err := object(stream["wsSettings"])
			if err != nil {
				return nil, err
			}
			headers := ws["headers"]
			if headers == nil {
				headers = Record{}
			}
			path := value(ws["path"])
			if path == "" {
				path = "/"
			}
			node["ws-opts"] = Record{"path": path, "headers": headers}
		}
		if network == "grpc" {
			grpc, err := object(stream["grpcSettings"])
			if err != nil {
				return nil, err
			}
			node["grpc-opts"] = Record{"grpc-service-name": value(grpc["serviceName"])}
		}
		security := value(stream["security"])
		if security == "tls" || security == "reality" {
			node["tls"] = true
			tls, err := object(stream["tlsSettings"])
			if err != nil {
				return nil, err
			}
			sni := value(tls["serverName"])
			if sni == "" {
				sni = value(record["domain"])
			}
			node["servername"] = sni
			if protocol == "hysteria2" || protocol == "tuic" {
				node["sni"] = sni
				alpn := tls["alpn"]
				if alpn == nil {
					alpn = []any{"h3"}
				}
				node["alpn"] = alpn
			}
		}
		if security == "reality" {
			reality, err := object(stream["realitySettings"])
			if err != nil {
				return nil, err
			}
			extra, err := object(reality["settings"])
			if err != nil {
				return nil, err
			}
			key := value(extra["publicKey"])
			if key == "" && value(reality["privateKey"]) != "" {
				raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(value(reality["privateKey"]), "="))
				if err != nil {
					return nil, errors.New("Reality 密钥格式无效")
				}
				private, err := ecdh.X25519().NewPrivateKey(raw)
				if err != nil {
					return nil, errors.New("Reality 密钥长度无效")
				}
				key = base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes())
			}
			if key == "" {
				return nil, errors.New("Reality 公钥缺失")
			}
			shortID := ""
			if ids, ok := reality["shortIds"].([]any); ok && len(ids) > 0 {
				shortID = value(ids[0])
			}
			sni := ""
			if names, ok := reality["serverNames"].([]any); ok && len(names) > 0 {
				sni = value(names[0])
			}
			node["servername"] = sni
			node["client-fingerprint"] = "chrome"
			node["reality-opts"] = Record{"public-key": key, "short-id": shortID, "support-x25519mlkem768": true}
		}
		result = append(result, node)
	}
	return result, nil
}
func (m *Manager) Inbounds(ctx context.Context, id string) (Record, error) {
	value, err := m.WithPanel(ctx, id, func(panel *Panel, record Record) (any, error) {
		result, err := panel.Request(ctx, "panel/api/inbounds/list", nil, "")
		if err != nil {
			return nil, err
		}
		input, ok := result.([]any)
		if !ok {
			return nil, errors.New("面板未返回有效的入站列表")
		}
		rows := []any{}
		for _, v := range input {
			row, err := object(v)
			if err != nil {
				return nil, err
			}
			row["shareLinks"] = []any{}
			version, versionErr := InboundVersion(row)
			if versionErr != nil {
				return nil, versionErr
			}
			row["editToken"] = version
			nodes, nodeErr := InboundNodes(row, record)
			if nodeErr != nil {
				row["shareError"] = nodeErr.Error()
			} else {
				uris := []any{}
				for _, node := range nodes {
					uri, err := links.Export(node)
					if err != nil {
						row["shareError"] = err.Error()
						continue
					}
					uris = append(uris, uri)
				}
				row["shareLinks"] = uris
			}
			rows = append(rows, row)
		}
		return Record{"server": publicServer(record), "inbounds": rows}, nil
	})
	if err != nil {
		return nil, err
	}
	return value.(map[string]any), nil
}
