package links

import (
	"encoding/base64"
	"encoding/json"
	"strconv"
	"strings"
)

func parseVMess(body string) (map[string]any, error) {
	body, _, _ = strings.Cut(body, "#")
	raw, err := decode64(body)
	if err != nil {
		return nil, ErrURI
	}
	var v map[string]any
	if json.Unmarshal([]byte(raw), &v) != nil || text(v["pcs"]) != "" || text(v["vcn"]) != "" {
		return nil, ErrURI
	}
	port, err := strconv.Atoi(text(v["port"]))
	if err != nil || port < 1 || port > 65535 || text(v["add"]) == "" || text(v["id"]) == "" {
		return nil, ErrURI
	}
	alterID := 0
	if aid := text(v["aid"]); aid != "" {
		alterID, err = strconv.Atoi(aid)
		if err != nil || alterID < 0 {
			return nil, ErrURI
		}
	}
	node := map[string]any{"name": text(v["ps"]), "type": "vmess", "server": text(v["add"]),
		"port": port, "uuid": text(v["id"]), "cipher": text(v["scy"]), "alterId": alterID}
	if node["name"] == "" {
		node["name"] = node["server"]
	}
	if node["cipher"] == "" {
		node["cipher"] = "auto"
	}
	switch strings.ToLower(text(v["tls"])) {
	case "tls", "1", "true":
		node["tls"] = true
	case "", "0", "false":
	default:
		return nil, ErrURI
	}
	for field, target := range map[string]string{"sni": "servername", "fp": "client-fingerprint"} {
		if value := text(v[field]); value != "" {
			node[target] = value
		}
	}
	if text(v["sni"]) == "" && text(v["host"]) != "" {
		node["servername"] = text(v["host"])
	}
	if value := text(v["alpn"]); value != "" {
		list := []any{}
		for _, protocol := range strings.Split(value, ",") {
			protocol = strings.TrimSpace(protocol)
			if protocol == "" {
				return nil, ErrURI
			}
			list = append(list, protocol)
		}
		node["alpn"] = list
	}
	switch strings.ToLower(text(v["insecure"])) {
	case "1", "true":
		node["skip-cert-verify"] = true
	case "0", "false":
		node["skip-cert-verify"] = false
	case "":
	default:
		return nil, ErrURI
	}
	network, header := text(v["net"]), text(v["type"])
	if header != "" && header != "none" && !(network == "grpc" && header == "gun") {
		return nil, ErrURI
	}
	switch network {
	case "", "tcp":
	case "ws":
		headers := map[string]any{}
		if host := text(v["host"]); host != "" {
			headers["Host"] = host
		}
		node["network"], node["ws-opts"] = network, map[string]any{"path": transportDefault(text(v["path"]), "/"), "headers": headers}
	case "grpc":
		service := text(v["path"])
		if service == "" {
			service = text(v["serviceName"])
		}
		node["network"], node["grpc-opts"] = network, map[string]any{"grpc-service-name": transportDefault(service, "grpc")}
	default:
		return nil, ErrURI
	}
	return node, nil
}

func exportVMess(node map[string]any, port string) (string, error) {
	for _, key := range []string{"http-opts", "h2-opts", "fingerprint", "reality-opts"} {
		if node[key] != nil {
			return "", ErrURI
		}
	}
	aid := text(node["alterId"])
	if aid == "" {
		aid = text(node["alter-id"])
	}
	if aid == "" {
		aid = "0"
	}
	v := map[string]any{"v": "2", "ps": node["name"], "add": node["server"], "port": port,
		"id": node["uuid"], "aid": aid, "scy": node["cipher"], "net": "tcp", "type": "none", "tls": ""}
	if node["tls"] == true {
		v["tls"] = "tls"
	}
	if sni := text(node["servername"]); sni != "" {
		v["sni"] = sni
	} else if sni := text(node["sni"]); sni != "" {
		v["sni"] = sni
	}
	if fp := text(node["client-fingerprint"]); fp != "" {
		v["fp"] = fp
	}
	if raw := node["skip-cert-verify"]; raw != nil {
		insecure, ok := raw.(bool)
		if !ok {
			return "", ErrURI
		}
		v["insecure"] = "0"
		if insecure {
			v["insecure"] = "1"
		}
	}
	if raw := node["alpn"]; raw != nil {
		var list []string
		switch values := raw.(type) {
		case []string:
			list = values
		case []any:
			for _, value := range values {
				protocol, ok := value.(string)
				if !ok {
					return "", ErrURI
				}
				list = append(list, protocol)
			}
		default:
			return "", ErrURI
		}
		for _, protocol := range list {
			if protocol == "" || strings.TrimSpace(protocol) != protocol || strings.ContainsAny(protocol, ",\r\n") {
				return "", ErrURI
			}
		}
		v["alpn"] = strings.Join(list, ",")
	}
	switch network := text(node["network"]); network {
	case "", "tcp":
	case "ws", "grpc":
		path, host, err := shareTransport(node, network)
		if err != nil {
			return "", err
		}
		v["net"], v["path"] = network, path
		if host != "" {
			v["host"] = host
		}
	default:
		return "", ErrURI
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return "", ErrURI
	}
	return "vmess://" + base64.StdEncoding.EncodeToString(raw), nil
}

// Only options representable in the client link are accepted. Otherwise
// callers report the node as skipped instead of emitting an altered route.
func shareTransport(node map[string]any, network string) (path, host string, err error) {
	raw := node[network+"-opts"]
	if raw == nil {
		return "", "", nil
	}
	options, ok := raw.(map[string]any)
	if !ok {
		return "", "", ErrURI
	}
	for key, value := range options {
		switch {
		case network == "grpc" && key == "grpc-service-name", network == "ws" && key == "path":
			var ok bool
			path, ok = value.(string)
			if !ok {
				return "", "", ErrURI
			}
		case network == "ws" && key == "headers":
			headers, ok := value.(map[string]any)
			if !ok || len(headers) > 1 {
				return "", "", ErrURI
			}
			for header, value := range headers {
				host, ok = value.(string)
				if !strings.EqualFold(header, "Host") || !ok {
					return "", "", ErrURI
				}
			}
		default:
			return "", "", ErrURI
		}
	}
	return path, host, nil
}
