package config

import (
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

// State returns an isolated JSON document; callers never retain references into
// repository state. Network operations must happen outside UpdateState.
func (r *Repository) State(id string) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	return stateRecord(index, id)
}
func stateRecord(index Document, id string) (Document, error) {
	if id == "" {
		id = "clash"
	}
	for _, v := range index["profiles"].([]any) {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("订阅索引格式无效")
		}
		if row["id"] == id {
			return row, nil
		}
	}
	return nil, errors.New("订阅不存在")
}
func (r *Repository) UpdateState(id string, change func(Document) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return err
	}
	if err = change(record); err != nil {
		return err
	}
	return r.writeIndex(index)
}

// BeginOwnership persists the encrypted pending credential before any remote
// write. A pending identity blocks profile deletion, copying and server rebinds.
func (r *Repository) BeginOwnership(id string, binding Document) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return nil, err
	}
	if binding["scope"] != "user" || binding["status"] != "provisioning" || stringValue(binding["pendingUser"]) == "" || stringValue(binding["operationId"]) == "" {
		return nil, errors.New("待创建用户记录无效")
	}
	for _, v := range index["profiles"].([]any) {
		owner := v.(map[string]any)
		for _, v := range rows(owner, "remoteNodes") {
			b, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("订阅绑定格式无效")
			}
			if b["serverId"] == binding["serverId"] && fmt.Sprint(b["inboundId"]) == fmt.Sprint(binding["inboundId"]) && (b["status"] == "active" || b["status"] == "provisioning") {
				if b["dedicated"] == true {
					return nil, errors.New("入站已被专属绑定，请使用原专属绑定入口")
				}
				if b["scope"] != "user" {
					return nil, errors.New("入站仍有旧版专属绑定，请先迁移")
				}
				if owner["id"] == record["id"] {
					return b, nil
				}
			}
		}
	}
	record["remoteNodes"] = append(rows(record, "remoteNodes"), binding)
	if err = r.writeIndex(index); err != nil {
		return nil, err
	}
	return binding, nil
}

func ownedBinding(record Document, operation string) (Document, error) {
	for _, v := range rows(record, "remoteNodes") {
		b, ok := v.(map[string]any)
		if ok && b["operationId"] == operation && (b["status"] == "active" || b["status"] == "provisioning") {
			return b, nil
		}
	}
	return nil, errors.New("用户归属记录已变化，请重新核对")
}

// ImportOwnedNode writes YAML before its completion marker. If index saving
// fails after YAML succeeds, the durable intent remains and retry deduplicates
// by credentials instead of producing a second node or a second remote user.
func (r *Repository) ImportOwnedNode(id, operation string, node Document) (Document, error) {
	return r.ImportOwnedNodeWithChain(id, operation, node, nil)
}

func (r *Repository) ImportOwnedNodeWithChain(id, operation string, node Document, chain *ServerChainImport) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	record, err := stateRecord(index, id)
	if err != nil {
		return nil, err
	}
	binding, err := ownedBinding(record, operation)
	if err != nil {
		return nil, err
	}
	if err = ValidateNode(node); err != nil {
		return nil, err
	}
	var chainRecords []any
	var profile Profile
	if chain != nil {
		chainRecords, err = prepareNamedChainRecord(record, binding, chain)
		if err != nil {
			return nil, err
		}
		profile, err = profileFrom(record)
		if err != nil {
			return nil, err
		}
		node["name"] = chain.Name
	}
	added := 0
	name := ""
	err = r.mutateLocked(id, func(doc Document) error {
		assignGroups := func() error {
			if chain == nil {
				return nil
			}
			return EditMembership(doc, Document{"name": name, "groups": chain.Groups}, groupOptions(doc, profile))
		}
		previousNames := map[string]bool{}
		if names, ok := binding["importedNames"].([]any); ok {
			for _, v := range names {
				previousNames[stringValue(v)] = true
			}
		}
		for _, v := range rows(doc, "proxies") {
			old := v.(map[string]any)
			same := true
			for _, key := range []string{"type", "server", "port", "uuid", "password"} {
				if fmt.Sprint(old[key]) != fmt.Sprint(node[key]) {
					same = false
					break
				}
			}
			owned := previousNames[stringValue(old["name"])] && old["type"] == node["type"] && old["uuid"] == node["uuid"] && old["password"] == node["password"]
			if same || owned {
				name = stringValue(old["name"])
				node["name"] = name
				if chain != nil && name != chain.Name {
					return errors.New("中转用户凭据已用于其他节点名称")
				}
				if err := EditNode(doc, "PUT", Document{"oldName": name, "config": node}); err != nil {
					return err
				}
				return assignGroups()
			}
		}
		base := stringValue(node["name"])
		used := map[string]bool{}
		for _, key := range []string{"proxies", "proxy-groups"} {
			for _, v := range rows(doc, key) {
				used[stringValue(v.(map[string]any)["name"])] = true
			}
		}
		for _, reserved := range []string{"DIRECT", "REJECT", "REJECT-DROP", "PASS"} {
			used[reserved] = true
		}
		if chain != nil && used[base] {
			return errors.New("链路名称已被使用")
		}
		name = base
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s (%d)", base, i)
		}
		node["name"] = name
		if err := EditNode(doc, "POST", Document{"config": node}); err != nil {
			return err
		}
		if chain != nil {
			added = 1
			return assignGroups()
		}
		blocked := map[string]bool{}
		for group := range excludedNodeGroups {
			blocked[group] = true
		}
		for _, v := range rows(record, "failovers") {
			if f, ok := v.(map[string]any); ok {
				blocked[stringValue(f["name"])] = true
				blocked[stringValue(f["groupName"])] = true
			}
		}
		for _, v := range rows(doc, "proxy-groups") {
			g := v.(map[string]any)
			if !blocked[stringValue(g["name"])] {
				g["proxies"] = append(rows(g, "proxies"), name)
			}
		}
		added = 1
		return nil
	})
	if err != nil {
		return nil, err
	}
	binding["status"] = "active"
	binding["error"] = ""
	binding["importedNames"] = []string{name}
	binding["importedNodes"] = []any{Document{"name": name, "identity": managednodes.Identity(node)}}
	if chain != nil {
		record["serverChains"] = chainRecords
	}
	delete(binding, "pendingUser")
	if err = r.writeIndex(index); err != nil {
		return nil, errors.New("节点文件已保存，归属标记待保存；请在同一入站重试")
	}
	return Document{"added": added, "existing": 1 - added, "bound": true, "names": []string{name}}, nil
}
