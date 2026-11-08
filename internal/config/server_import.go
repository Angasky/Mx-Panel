package config

import (
	"errors"
	"fmt"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

// HasInboundUsers selects the isolated-user import path. Callers hold the
// controller's server lock through the subsequent remote operation.
func (r *Repository) HasInboundUsers(server string, inbound int) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return false, err
	}
	for _, owner := range rows(index, "profiles") {
		for _, raw := range rows(owner.(Document), "remoteNodes") {
			binding, ok := raw.(Document)
			if !ok {
				return false, errors.New("订阅绑定记录无效")
			}
			if binding["serverId"] == server && bindingInboundID(binding, inbound) && binding["scope"] == "user" && (binding["status"] == "active" || binding["status"] == "provisioning") {
				return true, nil
			}
		}
	}
	return false, nil
}

// ImportUnboundServerNodes commits only live, unowned links. Ownership and quota
// are checked under the same repository mutex as the YAML transaction.
func (r *Repository) ImportUnboundServerNodes(profile, server string, inbound int, nodes []Document, now time.Time) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(nodes) == 0 || len(nodes) > 20000 {
		return nil, errors.New("没有可导入节点或数量超限")
	}
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	record, err := stateRecord(index, profile)
	if err != nil {
		return nil, err
	}
	info, err := TrafficInfo(record, now)
	if err != nil {
		return nil, err
	}
	if record["accessRevoked"] == true || info["expired"] == true || info["exhausted"] == true || info["enforce"] == true {
		return nil, errors.New("受限订阅必须导入独立认证用户，不能导入未绑定链接")
	}
	for _, owner := range rows(index, "profiles") {
		for _, raw := range rows(owner.(Document), "remoteNodes") {
			binding, ok := raw.(Document)
			if !ok {
				return nil, errors.New("订阅绑定记录无效")
			}
			if binding["serverId"] == server && fmt.Sprint(binding["inboundId"]) == fmt.Sprint(inbound) {
				return nil, errors.New("入站已有订阅归属或撤销记录，请使用独立用户导入")
			}
		}
	}
	added, existing := 0, 0
	names := []string{}
	err = r.mutateLocked(profile, func(doc Document) error {
		list := rows(doc, "proxies")
		identities := map[string]string{}
		used := map[string]bool{}
		for _, raw := range list {
			node := raw.(Document)
			name := stringValue(node["name"])
			used[name] = true
			if node["dialer-proxy"] == nil {
				identities[managednodes.Identity(node)] = name
			}
		}
		for _, raw := range rows(doc, "proxy-groups") {
			used[stringValue(raw.(Document)["name"])] = true
		}
		for _, source := range nodes {
			node := cloneConfig(source).(Document)
			if err := ValidateNode(node); err != nil {
				return err
			}
			hash := managednodes.Identity(node)
			if name, ok := identities[hash]; ok {
				existing++
				names = append(names, name)
				continue
			}
			base := stringValue(node["name"])
			name := base
			for i := 2; used[name]; i++ {
				name = fmt.Sprintf("%s-%02d", base, i)
			}
			node["name"] = name
			used[name] = true
			identities[hash] = name
			names = append(names, name)
			if err := EditNode(doc, "POST", Document{"config": node, "addToGroups": true}); err != nil {
				return err
			}
			added++
			if len(rows(doc, "proxies")) > 20000 {
				return errors.New("节点数量超过 20000")
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Document{"added": added, "existing": existing, "updated": 0, "names": names, "bound": false, "enforcementEnabled": false}, nil
}
