package config

import (
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

// Reserve the existing credential before enabling accounting remotely. Unlike
// BeginOwnership this never contains a credential that could recreate a user.
func (r *Repository) BeginDedicatedOwnership(profile string, binding, node Document) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	record, err := stateRecord(index, profile)
	if err != nil {
		return nil, err
	}
	if binding["dedicated"] != true || (binding["scope"] != "user" && binding["scope"] != "inbound") || binding["status"] != "provisioning" || stringValue(binding["operationId"]) == "" || (binding["scope"] == "user" && stringValue(binding["userHash"]) == "") || stringValue(binding["identityHash"]) == "" {
		return nil, errors.New("专属绑定身份无效")
	}
	if err := ValidateNode(node); err != nil {
		return nil, err
	}
	var existing Document
	for _, item := range rows(index, "profiles") {
		owner := item.(Document)
		for _, raw := range rows(owner, "remoteNodes") {
			other, ok := raw.(Document)
			if !ok {
				return nil, errors.New("绑定记录无效")
			}
			if other["serverId"] != binding["serverId"] || fmt.Sprint(other["inboundId"]) != fmt.Sprint(binding["inboundId"]) {
				continue
			}
			if owner["id"] == record["id"] && other["dedicated"] == true && other["scope"] == binding["scope"] && other["dedicatedEndpointHash"] == binding["dedicatedEndpointHash"] && other["userHash"] == binding["userHash"] && other["identityHash"] == binding["identityHash"] && (other["status"] == "active" || other["status"] == "provisioning") && other["monthlyPaused"] != true && other["inboundDeletePending"] == nil && existing == nil {
				existing = other
				continue
			}
			return nil, errors.New("入站已有其他归属、撤销历史或待核对操作，不能接管")
		}
		p, err := profileFrom(owner)
		if err != nil {
			return nil, err
		}
		doc, _, err := r.cachedRead(p)
		if err != nil {
			return nil, err
		}
		matches := 0
		for _, raw := range rows(doc, "proxies") {
			n := raw.(Document)
			if managednodes.Identity(n) == managednodes.Identity(node) || managednodes.Owns(binding, n) {
				matches++
				if owner["id"] != record["id"] || matches > 1 || managednodes.Identity(n) != managednodes.Identity(node) {
					return nil, errors.New("现有凭据被其他节点或订阅共用，不能专属接管")
				}
			}
		}
	}
	if existing != nil {
		return existing, nil
	}
	record["remoteNodes"] = append(rows(record, "remoteNodes"), binding)
	t, ok := record["traffic"].(Document)
	if !ok {
		t = Document{}
	}
	t["enabled"], t["enforce"] = true, true
	record["traffic"] = t
	if err := r.writeIndex(index); err != nil {
		return nil, err
	}
	return binding, nil
}
