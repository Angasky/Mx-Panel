package config

import "errors"

func defaultPolicyTemplate(index Document) string {
	id := stringValue(index["defaultPolicyTemplate"])
	if id == "" {
		return "blank"
	}
	return id
}

func (r *Repository) SetDefaultPolicyTemplate(id, expected string) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	if expected == "" || defaultPolicyTemplate(index) != expected {
		return nil, errors.New("默认模板已变化，请刷新模板列表后重试")
	}
	found := id == "blank"
	for _, item := range rows(index, "policyTemplates") {
		record, ok := item.(Document)
		if !ok {
			return nil, errors.New("策略模板记录无效")
		}
		if record["id"] == id {
			found = true
		}
	}
	if !found {
		return nil, errors.New("请选择内置模板或现有策略模板")
	}
	if id == "blank" {
		delete(index, "defaultPolicyTemplate")
	} else {
		index["defaultPolicyTemplate"] = id
	}
	if err = r.writeIndex(index); err != nil {
		return nil, err
	}
	return Document{"ok": true, "defaultTemplateId": id}, nil
}
