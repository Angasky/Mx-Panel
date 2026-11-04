package config

import (
	"errors"
	"sort"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

func (r *Repository) ServerProfiles(server string) ([]string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	ids := []string{}
	for _, v := range rows(index, "profiles") {
		p := v.(map[string]any)
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] == server {
				ids = append(ids, stringValue(p["id"]))
				break
			}
		}
	}
	return ids, nil
}

func (r *Repository) BindingSnapshot(server string) (map[string]bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	tokens := map[string]bool{}
	for _, v := range rows(index, "profiles") {
		p := v.(map[string]any)
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] == server {
				tokens[BindingToken(stringValue(p["id"]), b)] = true
			}
		}
	}
	return tokens, nil
}

func (r *Repository) ImportTargets(server string, ids []int) ([]Document, error) {
	if server == "" || len(ids) < 1 || len(ids) > 50 {
		return nil, errors.New("请选择服务器和 1–50 个入站")
	}
	wanted := map[int]bool{}
	for _, id := range ids {
		if id <= 0 || wanted[id] {
			return nil, errors.New("入站 ID 必须为不重复的正整数")
		}
		wanted[id] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	profiles, err := r.profiles()
	if err != nil {
		return nil, err
	}
	result := []Document{}
	for _, p := range profiles {
		row := Document{"id": p.ID, "name": p.Name, "importedInboundIds": []int{}}
		result = append(result, row)
		doc, _, err := r.cachedRead(p)
		if err != nil {
			row["error"] = "订阅配置读取失败"
			continue
		}
		imported := map[int]bool{}
		for _, v := range p.RemoteNodes {
			b, ok := v.(map[string]any)
			if !ok || b["serverId"] != server || b["status"] != "active" {
				continue
			}
			id, err := integer(b["inboundId"])
			if err != nil || !wanted[id] {
				continue
			}
			for _, n := range rows(doc, "proxies") {
				if managednodes.Owns(b, n.(map[string]any)) {
					imported[id] = true
					break
				}
			}
		}
		values := []int{}
		for id := range imported {
			values = append(values, id)
		}
		sort.Ints(values)
		row["importedInboundIds"] = values
	}
	return result, nil
}

// An authoritative snapshot may only change binding generations observed before
// fetching it. Registry metadata is durable before touching YAML, so failures retry.
func (r *Repository) ReconcileInventory(profile, server string, live map[int]bool, observed map[string]bool) (int, error) {
	return r.reconcileInventory(profile, server, observed, func(id int, _ Document) bool { return !live[id] })
}

// Standalone inventory describes only locally managed inbounds. An omitted
// row proves nothing, and a matching ID alone cannot identify an old binding.
func (r *Repository) ReconcileMissingCoreInbounds(profile, server string, missing map[int]Document, observed map[string]bool) (int, error) {
	return r.reconcileInventory(profile, server, observed, func(id int, binding Document) bool {
		row := missing[id]
		field := "missingLegacyIdentity"
		if binding["scope"] == "user" {
			field = "missingUserIdentity"
		}
		hash := stringValue(row[field])
		return len(hash) == 64 && binding["identityHash"] == hash
	})
}

func (r *Repository) reconcileInventory(profile, server string, observed map[string]bool, isMissing func(int, Document) bool) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return 0, err
	}
	p, err := stateRecord(index, profile)
	if err != nil {
		return 0, err
	}
	changed := false
	for _, v := range rows(p, "remoteNodes") {
		b := v.(map[string]any)
		if b["serverId"] != server || !observed[BindingToken(stringValue(p["id"]), b)] {
			continue
		}
		id, err := integer(b["inboundId"])
		if err != nil {
			return 0, err
		}
		if isMissing(id, b) && (b["status"] == "active" || b["status"] == "provisioning" || b["inboundDeletePending"] != nil) {
			b["status"] = "missing"
			b["error"] = "远端入站已不存在"
			delete(b, "inboundDeletePending")
			changed = true
		}
	}
	if changed {
		if err = r.writeIndex(index); err != nil {
			return 0, err
		}
	}
	return r.cleanupMissingLocked(profile)
}
func (r *Repository) CleanupMissing(profile string) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cleanupMissingLocked(profile)
}
func (r *Repository) cleanupMissingLocked(profile string) (int, error) {
	index, err := r.index()
	if err != nil {
		return 0, err
	}
	p, err := stateRecord(index, profile)
	if err != nil {
		return 0, err
	}
	bindings := []Document{}
	for _, v := range rows(p, "remoteNodes") {
		b := v.(map[string]any)
		if b["status"] == "missing" || b["localCleanupPending"] == true {
			bindings = append(bindings, b)
		}
	}
	if len(bindings) == 0 {
		return 0, nil
	}
	removed := 0
	err = r.mutateGuardedLocked(profile, func(doc Document) error {
		names := map[string]bool{}
		for _, v := range rows(doc, "proxies") {
			n := v.(map[string]any)
			for _, b := range bindings {
				if managednodes.Owns(b, n) {
					names[stringValue(n["name"])] = true
					break
				}
			}
		}
		for {
			changed := false
			for _, v := range rows(doc, "proxies") {
				n := v.(map[string]any)
				if names[stringValue(n["dialer-proxy"])] && !names[stringValue(n["name"])] {
					names[stringValue(n["name"])] = true
					changed = true
				}
			}
			if !changed {
				break
			}
		}
		next := []any{}
		for _, v := range rows(doc, "proxies") {
			if !names[stringValue(v.(map[string]any)["name"])] {
				next = append(next, v)
			}
		}
		doc["proxies"] = next
		for name := range names {
			replaceReferences(doc, name, "")
		}
		failovers := map[string]bool{}
		for _, v := range rows(p, "failovers") {
			if group, ok := v.(Document); ok {
				failovers[stringValue(group["name"])] = true
			}
		}
		for _, v := range rows(doc, "proxy-groups") {
			g := v.(map[string]any)
			if len(rows(g, "proxies")) == 0 && len(rows(g, "use")) == 0 {
				target := "DIRECT"
				if failovers[stringValue(g["name"])] {
					target = "REJECT"
				}
				g["proxies"] = []any{target}
			}
		}
		removed = len(names)
		return nil
	}, false)
	if err != nil {
		return 0, err
	}
	changed := removed > 0
	for _, b := range bindings {
		if b["localNodesRemovedAt"] == nil || b["localCleanupPending"] == true {
			changed = true
		}
		if b["localNodesRemovedAt"] == nil {
			b["localNodesRemovedAt"] = time.Now().Unix()
		}
		delete(b, "localCleanupPending")
	}
	if changed {
		if err = r.writeIndex(index); err != nil {
			return removed, err
		}
	}
	return removed, nil
}
