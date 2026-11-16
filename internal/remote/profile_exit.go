package remote

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"sort"
	"strings"
)

func profileExitTag(profile string) string {
	h := sha256.Sum256([]byte(profile))
	return "mxioc-user-exit-" + hex.EncodeToString(h[:12])
}
func profileExitRule(row Record) bool {
	if len(row) != 3 || row["type"] != "field" || !strings.HasPrefix(value(row["outboundTag"]), "mxioc-user-exit-") {
		return false
	}
	emails := anyStrings(row["user"])
	if len(emails) == 0 || len(emails) > 1000 {
		return false
	}
	for _, email := range emails {
		if !strings.HasPrefix(email, "mxioc-") || strings.ContainsAny(email, "\x00\r\n") {
			return false
		}
	}
	return true
}
func exitFragment(doc Record, tag string) (string, error) {
	outs := []any{}
	rules := []any{}
	for _, out := range anyRecords(doc["outbounds"]) {
		if out["tag"] == tag {
			outs = append(outs, out)
		} else if containsConfigString(out, tag) {
			return "", errors.New("用户出口被其他出站引用，未修改")
		}
	}
	routing, e := inboundObject(doc["routing"])
	if e != nil {
		return "", e
	}
	for _, r := range anyRecords(routing["rules"]) {
		if r["outboundTag"] == tag {
			if !profileExitRule(r) {
				return "", errors.New("用户出口路由被其他配置引用")
			}
			rules = append(rules, r)
		}
	}
	if len(outs) == 0 && len(rules) == 0 {
		return "", nil
	}
	if len(outs) != 1 || len(rules) != 1 {
		return "", errors.New("用户出口配置缺失或重复")
	}
	raw, _ := json.Marshal([]any{outs, rules})
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:]), nil
}
func planProfileExit(doc Record, profile string, emails []string, node Record, expected string) (Record, string, error) {
	if profile == "" || len(profile) > 128 {
		return nil, "", errors.New("套餐订阅标识无效")
	}
	tag := profileExitTag(profile)
	current, e := exitFragment(doc, tag)
	if e != nil {
		return nil, "", e
	}
	if current != expected {
		return nil, "", errors.New("用户出口归属已变化，未覆盖远端配置")
	}
	routing, e := inboundObject(doc["routing"])
	if e != nil {
		return nil, "", e
	}
	routing = maps.Clone(routing)
	outRows, ok := doc["outbounds"].([]any)
	if !ok || len(anyRecords(outRows)) != len(outRows) {
		return nil, "", errors.New("出站配置无效")
	}
	rawRules := routing["rules"]
	if rawRules != nil {
		r, ok := rawRules.([]any)
		if !ok || len(anyRecords(r)) != len(r) {
			return nil, "", errors.New("路由配置无效")
		}
	}
	next := maps.Clone(doc)
	outs := []any{}
	rules := []any{}
	for _, out := range anyRecords(outRows) {
		if out["tag"] != tag {
			outs = append(outs, out)
		}
	}
	for _, r := range anyRecords(rawRules) {
		if r["outboundTag"] != tag {
			rules = append(rules, r)
		}
	}
	if node != nil {
		if len(emails) == 0 || len(emails) > 1000 {
			return nil, "", errors.New("套餐没有可路由的独立代理用户")
		}
		unique := map[string]bool{}
		for _, email := range emails {
			if !strings.HasPrefix(email, "mxioc-") || strings.ContainsAny(email, "\x00\r\n") || unique[email] {
				return nil, "", errors.New("独立用户身份无效或重复")
			}
			unique[email] = true
		}
		emails = append([]string(nil), emails...)
		sort.Strings(emails)
		users := make([]any, len(emails))
		for i, email := range emails {
			users[i] = email
		}
		out, e := NodeOutbound(node, tag)
		if e != nil {
			return nil, "", e
		}
		if len(outs) == 0 {
			return nil, "", errors.New("服务器缺少默认出站，不能将用户出口作为默认出站")
		}
		outs = append(outs, out)
		rules = append([]any{Record{"type": "field", "user": users, "outboundTag": tag}}, rules...)
	}
	next["outbounds"] = outs
	routing["rules"] = rules
	next["routing"] = routing
	fingerprint, e := exitFragment(next, tag)
	return next, fingerprint, e
}

// SetProfileExit only changes a package-specific outbound and authenticated-user
// route. The expected fragment and full pending candidate are journaled before IO.
type profileExitOperationKey struct{}

func (m *Manager) SetProfileExit(ctx context.Context, id, profile string, emails []string, node Record) (Record, error) {
	ctx = context.WithValue(ctx, profileExitOperationKey{}, true)
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		return m.setProfileExitCore(ctx, id, profile, emails, node, kind, record, run)
	})
}
func (m *Manager) setProfileExitCore(ctx context.Context, id, profile string, emails []string, node Record, kind string, record Record, run coreRunner) (Record, error) {
	if kind != "xray" {
		return nil, errors.New("用户专属出口当前需要独立 Xray")
	}
	if value(record["coreUserPending"]) != "" {
		return nil, errors.New("服务器有未完成的用户写入，请先核对")
	}
	raw, doc, e := readCore(ctx, kind, run)
	if e != nil {
		return nil, e
	}
	owners, e := inboundObject(record["profileExitOwnership"])
	if e != nil {
		return nil, e
	}
	expected := value(owners[profile])
	req, _ := json.Marshal([]any{profile, emails, node})
	h := sha256.Sum256(req)
	requestHash := hex.EncodeToString(h[:])
	journal := Record{}
	if sealed := value(record["profileExitPending"]); sealed != "" {
		journal, e = m.OpenUser(sealed)
		if e != nil {
			return nil, e
		}
		if journal["request"] != requestHash || journal["profile"] != profile {
			return nil, errors.New("服务器有待核对的用户出口操作，请重试原请求")
		}
	}
	recovering := len(journal) > 0
	var next Record
	var fingerprint string
	if len(journal) > 0 {
		if coreConfigHash(raw) != journal["before"] && coreConfigHash(raw) != journal["after"] {
			return nil, errors.New("用户出口写入期间远端配置变化，请人工核对")
		}
		next, _ = journal["next"].(Record)
		fingerprint = value(journal["fingerprint"])
	} else {
		next, fingerprint, e = planProfileExit(doc, profile, emails, node, expected)
		if e != nil {
			return nil, e
		}
		nextBytes, _ := json.Marshal(next)
		journal = Record{"profile": profile, "request": requestHash, "before": coreConfigHash(raw), "after": coreConfigHash(nextBytes), "next": next, "previous": string(raw), "fingerprint": fingerprint}
		sealed, e := m.SealUser(journal)
		if e != nil {
			return nil, e
		}
		if e = m.saveProfileExitJournal(id, value(record["profileExitPending"]), sealed, profile, "", false); e != nil {
			return nil, e
		}
		record["profileExitPending"] = sealed
	}
	if coreConfigHash(raw) != journal["after"] || recovering {
		if _, e = applyCore(ctx, kind, raw, next, "", run); e != nil {
			return nil, e
		}
	}
	if e = m.saveProfileExitJournal(id, value(record["profileExitPending"]), "", profile, fingerprint, true); e != nil {
		return nil, e
	}
	return Record{"updated": true, "enabled": node != nil, "users": len(emails)}, nil
}
func (m *Manager) saveProfileExitJournal(id, expected, pending, profile, fingerprint string, commit bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return e
	}
	row, e := find(data, id)
	if e != nil {
		return e
	}
	if value(row["profileExitPending"]) != expected {
		return errors.New("用户出口恢复状态已变化")
	}
	if commit {
		owners, e := inboundObject(row["profileExitOwnership"])
		if e != nil {
			return e
		}
		if fingerprint == "" {
			delete(owners, profile)
		} else {
			owners[profile] = fingerprint
		}
		row["profileExitOwnership"] = owners
	}
	if pending == "" {
		delete(row, "profileExitPending")
	} else {
		row["profileExitPending"] = pending
	}
	return m.flush(data)
}

// CancelProfileExit restores only an exact pending candidate or its recorded
// baseline. Any external change is refused rather than overwritten.
func (m *Manager) CancelProfileExit(ctx context.Context, id, profile string) error {
	ctx = context.WithValue(ctx, profileExitOperationKey{}, true)
	_, e := m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		sealed := value(record["profileExitPending"])
		if sealed == "" {
			return Record{"ok": true}, nil
		}
		j, e := m.OpenUser(sealed)
		if e != nil {
			return nil, e
		}
		if j["profile"] != profile {
			return nil, errors.New("其他套餐的出口操作未完成")
		}
		raw, _, e := readCore(ctx, kind, run)
		if e != nil {
			return nil, e
		}
		if coreConfigHash(raw) != j["before"] && coreConfigHash(raw) != j["after"] {
			return nil, errors.New("远端配置已被外部修改，不能自动撤回")
		}
		previous, e := inboundObject(j["previous"])
		if e != nil || previous == nil {
			return nil, errors.New("原出口配置恢复记录无效")
		}
		if _, e = applyCore(ctx, kind, raw, previous, "", run); e != nil {
			return nil, e
		}
		e = m.saveProfileExitJournal(id, sealed, "", profile, "", false)
		return Record{"ok": e == nil}, e
	})
	return e
}
