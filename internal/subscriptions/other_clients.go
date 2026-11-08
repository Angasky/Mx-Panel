package subscriptions

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"go.yaml.in/yaml/v3"
)

// Each target has its own schema and an explicit supported subset.
func otherClientNode(node Record, format, name string) (any, error) {
	kind := text(node["type"])
	if value, exists := node["udp"]; exists {
		if _, ok := value.(bool); !ok {
			return nil, errors.New("UDP 设置类型无效")
		}
	}
	switch format {
	case "surfboard":
		if kind != "ss" && kind != "trojan" && kind != "http" && kind != "socks5" {
			return nil, errors.New("当前 Surfboard 导出仅适配基础 SS、Trojan、HTTP 和 SOCKS5")
		}
		copy := Record{}
		for k, v := range node {
			copy[k] = v
		}
		delete(copy, "udp")
		line, err := surgeNode(copy)
		if err != nil {
			return nil, err
		}
		if v, exists := node["udp"]; exists {
			b, ok := v.(bool)
			if !ok {
				return nil, errors.New("UDP 设置类型无效")
			}
			if kind == "http" && b {
				return nil, errors.New("HTTP 不能转发 UDP")
			}
			if kind != "http" {
				line += fmt.Sprintf(", udp-relay=%t", b)
			}
		}
		return name + " = " + line, nil
	case "quantumult-x":
		if kind != "ss" && kind != "trojan" && kind != "http" {
			return nil, errors.New("当前 Quantumult X 导出仅适配基础 SS、Trojan 和 HTTP")
		}
		copy := Record{}
		for k, v := range node {
			copy[k] = v
		}
		delete(copy, "udp")
		if _, err := surgeNode(copy); err != nil {
			return nil, err
		}
		host := strings.Trim(text(node["server"]), "[]")
		port := text(node["port"])
		prefix := kind
		if kind == "ss" {
			prefix = "shadowsocks"
		}
		params := []string{prefix + "=" + net.JoinHostPort(host, port)}
		if kind == "ss" {
			params = append(params, "method="+text(node["cipher"]))
		}
		for _, key := range []string{"username", "password"} {
			if v := text(node[key]); v != "" {
				params = append(params, key+"="+v)
			}
		}
		if kind == "trojan" || node["tls"] == true {
			params = append(params, "over-tls=true")
			sni := text(node["sni"])
			if sni == "" {
				sni = text(node["servername"])
			}
			if sni != "" {
				params = append(params, "tls-host="+sni)
			}
			params = append(params, fmt.Sprintf("tls-verification=%t", node["skip-cert-verify"] != true))
		}
		if v, exists := node["tfo"]; exists {
			params = append(params, fmt.Sprintf("fast-open=%t", v))
		}
		if v, exists := node["udp"]; exists {
			b, ok := v.(bool)
			if !ok || kind == "http" && b {
				return nil, errors.New("UDP 设置不兼容")
			}
			params = append(params, fmt.Sprintf("udp-relay=%t", b))
		}
		params = append(params, "tag="+name)
		return strings.Join(params, ", "), nil
	case "stash":
		// A new minimal YAML document; never relabel a complete Mihomo configuration.
		if kind != "ss" && kind != "trojan" && kind != "http" && kind != "socks5" && kind != "vmess" {
			return nil, errors.New("当前 Stash 导出仅适配基础 SS、Trojan、HTTP、SOCKS5 和 VMess")
		}
		var err error
		if kind == "vmess" {
			_, err = loonNode(node)
		} else {
			copy := Record{}
			for k, v := range node {
				copy[k] = v
			}
			if kind == "trojan" {
				delete(copy, "udp")
			}
			_, err = surgeNode(copy)
		}
		if err != nil {
			return nil, err
		}
		copy := Record{}
		for k, v := range node {
			copy[k] = v
		}
		copy["name"] = name
		return copy, nil
	case "egern":
		if kind != "ss" && kind != "trojan" && kind != "http" && kind != "socks5" {
			return nil, errors.New("当前 Egern 导出仅适配基础 SS、Trojan、HTTP 和 SOCKS5")
		}
		if kind == "http" || kind == "socks5" {
			if node["tls"] == true {
				return nil, errors.New("Egern 当前适配不包含 HTTP/SOCKS TLS 包装")
			}
		}
		if node["skip-cert-verify"] != nil && node["skip-cert-verify"] != false {
			return nil, errors.New("Egern 当前适配不映射证书校验扩展")
		}
		copy := Record{}
		for k, v := range node {
			copy[k] = v
		}
		if kind == "trojan" {
			delete(copy, "udp")
		}
		if _, err := surgeNode(copy); err != nil {
			return nil, err
		}
		port, _ := strconv.Atoi(text(node["port"]))
		p := Record{"name": name, "server": text(node["server"]), "port": port}
		for _, key := range []string{"username", "password", "tfo"} {
			if v, ok := node[key]; ok {
				p[key] = v
			}
		}
		if v, ok := node["udp"]; ok {
			if _, ok = v.(bool); !ok {
				return nil, errors.New("UDP 类型无效")
			}
			if kind == "http" && v == true {
				return nil, errors.New("HTTP 不支持 UDP")
			}
			if kind != "http" {
				p["udp_relay"] = v
			}
		}
		if kind == "ss" {
			p["method"] = node["cipher"]
			kind = "shadowsocks"
		}
		sni := text(node["sni"])
		if sni == "" {
			sni = text(node["servername"])
		}
		if sni != "" {
			p["sni"] = sni
		}
		return Record{kind: p}, nil
	}
	return nil, errors.New("未知客户端格式")
}
func convertOtherClient(source config.Subscription, format string) (Export, error) {
	out := Export{Skipped: []Record{}}
	nodes := []any{}
	lines, names := []string{}, []string{}
	for i, node := range objects(source.Document["proxies"]) {
		name := fmt.Sprintf("MX-%d ", i+1) + strings.ReplaceAll(strings.TrimPrefix(shadowrocketName(text(node["name"]), strconv.Itoa(i), false), "MX-N-"), "/", " ")
		item, e := otherClientNode(node, format, name)
		if e != nil {
			out.Skipped = append(out.Skipped, Record{"name": node["name"], "type": node["type"], "reason": e.Error()})
			continue
		}
		nodes = append(nodes, item)
		names = append(names, name)
		if line, ok := item.(string); ok {
			lines = append(lines, line)
		}
	}
	out.Count = len(nodes)
	if out.Count == 0 {
		return out, errors.New("没有可导出的兼容节点")
	}
	switch format {
	case "quantumult-x":
		out.Body = []byte("# MXIOC: manual selection; original rules are not included.\n[server_local]\n" + strings.Join(lines, "\n") + "\n[policy]\nstatic=MX-PROXY, " + strings.Join(names, ", ") + "\n[filter_local]\nfinal, MX-PROXY\n")
	case "surfboard":
		out.Body = []byte("# MXIOC: manual selection; original rules are not included.\n[Proxy]\n" + strings.Join(lines, "\n") + "\n[Proxy Group]\nMX-PROXY = select, " + strings.Join(names, ", ") + "\n[Rule]\nFINAL,MX-PROXY\n")
	case "stash":
		body, e := yaml.Marshal(Record{"mode": "rule", "proxies": nodes, "proxy-groups": []any{Record{"name": "MX-PROXY", "type": "select", "proxies": names}}, "rules": []string{"MATCH,MX-PROXY"}})
		out.Body = body
		return out, e
	case "egern":
		body, e := yaml.Marshal(Record{"allow_external_connections": false, "proxies": nodes, "policy_groups": []any{Record{"select": Record{"name": "MX-PROXY", "policies": names}}}, "rules": []any{Record{"default": Record{"policy": "MX-PROXY"}}}})
		out.Body = body
		return out, e
	}
	return out, nil
}
