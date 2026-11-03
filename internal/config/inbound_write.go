package config

import (
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func bindingInboundID(b Document, id int) bool {
	n, err := integer(b["inboundId"])
	return err == nil && n == id
}

func (r *Repository) CheckInboundAvailable(server string, ids ...int) error {
	wanted := map[int]bool{}
	for _, id := range ids {
		wanted[id] = true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	for _, v := range rows(index, "profiles") {
		for _, v := range rows(v.(map[string]any), "remoteNodes") {
			b := v.(map[string]any)
			id, e := integer(b["inboundId"])
			if b["serverId"] == server && e == nil && wanted[id] && b["inboundDeletePending"] != nil {
				return errors.New("入站删除结果待核对，请刷新服务器列表或重试删除")
			}
		}
	}
	return nil
}

func checkInboundBinding(row, binding Document) error {
	if binding["scope"] == "user" {
		_, err := remote.FindUser(row, binding, binding["status"] == "provisioning")
		return err
	}
	actual, err := remote.LegacyInboundIdentity(row)
	if err != nil {
		return err
	}
	if expected := stringValue(binding["identityHash"]); expected != "" && expected != actual {
		return errors.New("入站与订阅绑定身份不一致，请先核对远端配置")
	}
	return nil
}

// Guards inspect fresh durable state; callers hold all affected profile locks.
func (r *Repository) GuardInboundEdit(server string, id int, old, next Document) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	for _, v := range rows(index, "profiles") {
		for _, v := range rows(v.(map[string]any), "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] != server || !bindingInboundID(b, id) {
				continue
			}
			if b["inboundDeletePending"] != nil {
				return errors.New("入站删除结果待核对，请先刷新列表")
			}
			if b["status"] == "provisioning" {
				return errors.New("该入站有创建结果待核对的订阅用户，请先重试核对")
			}
			if b["status"] != "active" {
				continue
			}
			if err = checkInboundBinding(old, b); err != nil {
				return err
			}
			if err = checkInboundBinding(next, b); err != nil {
				return err
			}
			if b["scope"] != "user" {
				a, e := remote.LegacyInboundIdentity(old)
				if e != nil {
					return e
				}
				z, e := remote.LegacyInboundIdentity(next)
				if e != nil {
					return e
				}
				if a != z {
					return errors.New("该入站仍有整入站订阅绑定，请保留端口、协议和用户配置")
				}
			}
		}
	}
	return nil
}

func (r *Repository) BeginInboundDelete(server string, id int, expected string, old Document, observed map[string]bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	changed := false
	for _, v := range rows(index, "profiles") {
		p := v.(map[string]any)
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] != server || !bindingInboundID(b, id) || !observed[BindingToken(stringValue(p["id"]), b)] {
				continue
			}
			if b["status"] != "active" && b["status"] != "provisioning" {
				continue
			}
			if old != nil {
				if err = checkInboundBinding(old, b); err != nil {
					return err
				}
			}
			b["inboundDeletePending"] = Document{"expected": expected, "at": time.Now().Unix()}
			changed = true
		}
	}
	if changed {
		return r.writeIndex(index)
	}
	return nil
}

func (r *Repository) ConfirmInboundDeleted(server string, id int, observed map[string]bool) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return 0, err
	}
	profiles := []string{}
	changed := false
	for _, v := range rows(index, "profiles") {
		p := v.(map[string]any)
		affected := false
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] != server || !bindingInboundID(b, id) || !observed[BindingToken(stringValue(p["id"]), b)] {
				continue
			}
			if b["status"] == "active" || b["status"] == "provisioning" || b["inboundDeletePending"] != nil || b["localCleanupPending"] == true {
				b["status"] = "missing"
				b["error"] = "远端入站已删除"
				b["localCleanupPending"] = true
				delete(b, "inboundDeletePending")
				changed = true
				affected = true
			}
		}
		if affected {
			profiles = append(profiles, stringValue(p["id"]))
		}
	}
	if changed {
		if err = r.writeIndex(index); err != nil {
			return 0, err
		}
	}
	count := 0
	for _, p := range profiles {
		n, e := r.cleanupMissingLocked(p)
		count += n
		if e != nil {
			return count, e
		}
	}
	return count, nil
}
