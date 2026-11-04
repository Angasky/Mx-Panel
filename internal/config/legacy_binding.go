package config

import (
	"errors"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

func LegacyCounterSource(source any) bool {
	switch source {
	case nil, "", "inbound", "authenticated-client":
		return true
	}
	return false
}

// MigrateLegacyBinding checks that the existing connection belongs to exactly
// one profile before changing only its accounting and ownership metadata.
// A nil settle callback validates ownership without writing.
func (r *Repository) MigrateLegacyBinding(profile string, position int, token string, proposed, node Document, settle func(Document, Document) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	record, err := stateRecord(index, profile)
	if err != nil {
		return err
	}
	profile = stringValue(record["id"])
	bindings := rows(record, "remoteNodes")
	if position < 0 || position >= len(bindings) {
		return errors.New("绑定记录已变化，请刷新")
	}
	binding := bindings[position].(Document)
	if BindingToken(profile, binding) != token || binding["status"] != "active" || binding["scope"] == "user" ||
		!LegacyCounterSource(binding["counterSource"]) || binding["counterSource"] != proposed["counterSource"] || binding["monthlyPaused"] == true ||
		binding["monthlyBaselinePending"] == true || binding["inboundDeletePending"] != nil {
		return errors.New("旧绑定状态已变化或不满足自动迁移条件")
	}
	target, err := integer(binding["inboundId"])
	if err != nil || target <= 0 {
		return errors.New("旧绑定入站 ID 无效")
	}
	identity := managednodes.Identity(node)
	var name string
	for _, item := range rows(index, "profiles") {
		owner := item.(Document)
		for i, item := range rows(owner, "remoteNodes") {
			other := item.(Document)
			if owner["id"] == profile && i == position {
				continue
			}
			if other["serverId"] == binding["serverId"] && bindingInboundID(other, target) &&
				(other["status"] == "active" || other["status"] == "provisioning" || other["inboundDeletePending"] != nil) {
				return errors.New("入站还有其他活动或待核对的订阅绑定")
			}
		}
		p, err := profileFrom(owner)
		if err != nil {
			return err
		}
		doc, _, err := r.cachedRead(p)
		if err != nil {
			return err
		}
		for _, item := range rows(doc, "proxies") {
			existing := item.(Document)
			if managednodes.Identity(existing) != identity && !managednodes.Owns(proposed, existing) {
				continue
			}
			if owner["id"] != profile || name != "" || managednodes.Identity(existing) != identity {
				return errors.New("已有连接与入站不一致或凭据被多个节点共用")
			}
			name = stringValue(existing["name"])
		}
	}
	if name == "" {
		return errors.New("当前订阅中找不到与远端身份一致的节点")
	}
	if settle == nil {
		return nil
	}
	if err := settle(record, binding); err != nil {
		return err
	}
	for _, key := range []string{"scope", "identityHash", "userEmail", "userHash", "operationId"} {
		binding[key] = proposed[key]
	}
	if proposed["legacyMeterRetained"] == true {
		binding["legacyMeterRetained"] = true
	}
	binding["importedNames"] = []any{name}
	binding["importedNodes"] = []any{Document{"name": name, "identity": identity}}
	bindingErrors(record)
	return r.writeIndex(index)
}
