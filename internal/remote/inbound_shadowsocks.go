package remote

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

func shadowsocks2022Key(method, key string, multi bool) bool {
	size := 0
	switch method {
	case "2022-blake3-aes-128-gcm":
		size = 16
	case "2022-blake3-aes-256-gcm":
		size = 32
	case "2022-blake3-chacha20-poly1305":
		if !multi {
			size = 32
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(key)
	return size != 0 && err == nil && len(decoded) == size && base64.StdEncoding.EncodeToString(decoded) == key
}

func shadowsocksInboundNodes(settings, stream Record, makeNode func() Record) ([]Record, error) {
	if security := value(stream["security"]); security != "" && security != "none" {
		return nil, errors.New("Shadowsocks TLS / Reality 包装尚未适配，未导出不完整连接")
	}
	if network := value(stream["network"]); network != "" && network != "tcp" && network != "raw" {
		return nil, errors.New("Shadowsocks 传输包装尚未适配，未导出不完整连接")
	}
	method, password := value(settings["method"]), value(settings["password"])
	raw, multi := settings["clients"]
	if users, exists := settings["users"]; exists {
		if multi {
			return nil, errors.New("Shadowsocks 用户列表不明确，未导出连接")
		}
		raw, multi = users, true
	}
	modern := strings.HasPrefix(method, "2022-")
	if !multi {
		if method == "" || password == "" {
			return []Record{}, nil
		}
		if modern && !shadowsocks2022Key(method, password, false) {
			return nil, errors.New("SS2022 服务端密钥或加密方式无效")
		}
		node := makeNode()
		node["type"], node["cipher"], node["password"] = "ss", method, password
		return []Record{node}, nil
	}
	clients, ok := raw.([]any)
	if !ok {
		return nil, errors.New("Shadowsocks 用户列表格式无效")
	}
	if modern && !shadowsocks2022Key(method, password, true) {
		return nil, errors.New("SS2022 多用户服务端密钥或加密方式无效")
	}
	nodes := []Record{}
	for index, raw := range clients {
		client, err := object(raw)
		if err != nil {
			return nil, err
		}
		if client["enable"] == false {
			continue
		}
		userMethod, userPassword := value(client["method"]), value(client["password"])
		cipher := method
		if modern {
			if userMethod != "" || !shadowsocks2022Key(method, userPassword, true) {
				return nil, errors.New("SS2022 用户密钥或加密方式无效")
			}
			userPassword = password + ":" + userPassword
		} else {
			cipher = userMethod
			if strings.HasPrefix(cipher, "2022-") {
				return nil, errors.New("SS2022 多用户缺少对应的服务端加密方式和密钥")
			}
		}
		if cipher == "" || userPassword == "" {
			return nil, errors.New("Shadowsocks 用户缺少密码或加密方式")
		}
		node := makeNode()
		if len(clients) > 1 {
			label := value(client["email"])
			if label == "" {
				label = value(client["name"])
			}
			if label == "" {
				label = fmt.Sprint(index + 1)
			}
			node["name"] = value(node["name"]) + " / " + label
		}
		node["type"], node["cipher"], node["password"] = "ss", cipher, userPassword
		nodes = append(nodes, node)
	}
	return nodes, nil
}
