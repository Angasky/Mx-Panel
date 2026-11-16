package config

import "errors"

// NodeProbeTargets returns only saved endpoint metadata, never credentials.
// Release the repository lock before any network operation.
func (r *Repository) NodeProbeTargets(id string, names []string) ([]Document, error) {
	if len(names) == 0 || len(names) > 30 {
		return nil, errors.New("每次请选择 1–30 个节点")
	}
	selected := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 1024 || selected[name] {
			return nil, errors.New("节点选择无效或重复")
		}
		selected[name] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	doc, _, err := r.cachedRead(p)
	if err != nil {
		return nil, err
	}
	found := map[string]Document{}
	for _, item := range rows(doc, "proxies") {
		n := item.(Document)
		name := stringValue(n["name"])
		if !selected[name] {
			continue
		}
		if found[name] != nil {
			return nil, errors.New("节点名称重复，请先修正配置")
		}
		port, _ := integer(n["port"])
		found[name] = Document{"name": name, "type": n["type"], "host": n["server"], "port": port, "network": n["network"], "transport": n["transport"], "chain": stringValue(n["dialer-proxy"]) != "", "tls": n["tls"], "sni": n["sni"], "servername": n["servername"], "alpn": cloneConfig(n["alpn"]), "reality": n["reality-opts"] != nil}
	}
	result := make([]Document, 0, len(names))
	for _, name := range names {
		if found[name] == nil {
			return nil, errors.New("所选节点已变化，请刷新后重试")
		}
		result = append(result, found[name])
	}
	return result, nil
}

// ProbeNodeConfig is a private snapshot used only by authenticated administrator
// diagnostics. It is never included in a diagnostic response.
func (r *Repository) ProbeNodeConfig(id, name string) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, e := r.profile(id)
	if e != nil {
		return nil, e
	}
	doc, _, e := r.cachedRead(p)
	if e != nil {
		return nil, e
	}
	var found Document
	for _, raw := range rows(doc, "proxies") {
		n := raw.(Document)
		if n["name"] == name {
			if found != nil {
				return nil, errors.New("节点名称重复")
			}
			if stringValue(n["dialer-proxy"]) != "" {
				return nil, errors.New("请选择普通落地节点，暂不测试客户端链式代理")
			}
			found = cloneConfig(n).(Document)
		}
	}
	if found == nil {
		return nil, errors.New("节点已变化，请刷新后重试")
	}
	return found, nil
}
