package config

import (
	"errors"
	"fmt"
)

// ImportSubscription commits the whole batch under one repository transaction.
// Network reads must be completed before calling it. Re-resolve groups and
// conflicts here so a stale preview never overwrites a newer configuration.
func (r *Repository) ImportSubscription(id string, nodes []map[string]any, conflict string, groups any, skipped int) (Document, error) {
	if conflict != "rename" && conflict != "replace" && conflict != "skip" {
		return nil, errors.New("重名处理方式无效")
	}
	if len(nodes) == 0 || len(nodes) > 20000 {
		return nil, errors.New("没有可导入节点或节点数量超过限制")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	added, replaced := 0, 0
	names := []any{}
	err = r.mutateLocked(id, func(doc Document) error {
		allowed := groupOptions(doc, p)
		available := map[string]bool{}
		selected := map[string]bool{}
		for _, name := range allowed {
			available[name] = true
			if groups == nil {
				selected[name] = true
			}
		}
		if groups != nil {
			list, ok := groups.([]any)
			if !ok {
				return errors.New("请选择策略组")
			}
			for _, value := range list {
				name, ok := value.(string)
				if !ok || !available[name] {
					return errors.New("策略组已变化，请刷新后重试")
				}
				selected[name] = true
			}
		}
		owned := map[string]bool{}
		for _, value := range p.RemoteNodes {
			b, ok := value.(map[string]any)
			if !ok {
				continue
			}
			if b["status"] != "active" && b["status"] != "provisioning" {
				continue
			}
			for _, name := range rows(b, "importedNames") {
				owned[stringValue(name)] = true
			}
		}
		list := rows(doc, "proxies")
		positions := map[string]int{}
		used := map[string]bool{}
		for i, value := range list {
			name := stringValue(value.(map[string]any)["name"])
			positions[name] = i
			used[name] = true
		}
		for _, value := range rows(doc, "proxy-groups") {
			used[stringValue(value.(map[string]any)["name"])] = true
		}
		suffix := map[string]int{}
		affected := map[string]bool{}
		ordered := []string{}
		for _, source := range nodes {
			node := cloneConfig(source).(Document)
			delete(node, "dialer-proxy")
			if err := ValidateNode(node); err != nil {
				return err
			}
			name := stringValue(node["name"])
			switch name {
			case "DIRECT", "REJECT", "REJECT-DROP", "PASS":
				return errors.New("节点名称不能与内置动作冲突")
			}
			index, exists := positions[name]
			if exists && conflict == "skip" {
				skipped++
				continue
			}
			if exists && conflict == "replace" {
				if owned[name] {
					return errors.New("节点拥有服务器专属用户，请改用重命名导入")
				}
				list[index] = node
				replaced++
			} else {
				base := name
				if used[name] {
					n := suffix[base]
					if n < 2 {
						n = 2
					}
					for {
						name = fmt.Sprintf("%s-%02d", base, n)
						n++
						if !used[name] {
							break
						}
					}
					suffix[base] = n
				}
				node["name"] = name
				if err := ValidateNode(node); err != nil {
					return err
				}
				positions[name] = len(list)
				used[name] = true
				list = append(list, node)
				added++
			}
			if !affected[name] {
				affected[name] = true
				ordered = append(ordered, name)
			}
			if len(names) < 30 {
				names = append(names, name)
			}
		}
		if added+replaced == 0 {
			return errors.New("没有节点被导入，请检查重复处理方式或订阅内容")
		}
		doc["proxies"] = list
		// Update every eligible group once, rather than rescanning it per node.
		for _, value := range rows(doc, "proxy-groups") {
			group := value.(map[string]any)
			name := stringValue(group["name"])
			if !available[name] {
				continue
			}
			next := []any{}
			for _, ref := range rows(group, "proxies") {
				s, _ := ref.(string)
				if !affected[s] {
					next = append(next, ref)
				}
			}
			if selected[name] {
				for _, nodeName := range ordered {
					next = append(next, nodeName)
				}
			}
			providers := rows(group, "use")
			if len(next) == 0 && len(providers) == 0 {
				return errors.New("移除后策略组为空，请先添加其他节点")
			}
			group["proxies"] = next
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Document{"added": added, "replaced": replaced, "skipped": skipped, "names": names}, nil
}
