package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"time"
)

type RotationProfile struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Custom bool   `json:"custom"`
}
type SubscriptionRotation struct {
	Profiles []RotationProfile `json:"profiles"`
	Revision string            `json:"revision"`
	Backup   string            `json:"backup,omitempty"`
}

// ReviewSubscriptionRotation rotates download capabilities only, under one
// index transaction. No node credentials, quotas, grants or remote resources change.
func (r *Repository) ReviewSubscriptionRotation(ids []string, expected string, apply bool) (SubscriptionRotation, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := SubscriptionRotation{Profiles: []RotationProfile{}}
	if len(ids) == 0 || len(ids) > 1000 {
		return v, errors.New("请选择 1–1000 份订阅")
	}
	selected := map[string]bool{}
	for _, id := range ids {
		if id == "" || len(id) > 128 || selected[id] {
			return v, errors.New("订阅选择无效或重复")
		}
		selected[id] = true
	}
	index, err := r.index()
	if err != nil {
		return v, err
	}
	current, _ := json.Marshal(index)
	used := map[string]bool{}
	targets := []Document{}
	for _, item := range rows(index, "profiles") {
		p := item.(Document)
		used[stringValue(p["slug"])] = true
		if !selected[stringValue(p["id"])] {
			continue
		}
		delete(selected, stringValue(p["id"]))
		targets = append(targets, p)
		v.Profiles = append(v.Profiles, RotationProfile{ID: stringValue(p["id"]), Name: stringValue(p["name"]), Custom: p["customSlug"] == true})
	}
	if len(selected) != 0 {
		return v, errors.New("所选订阅已不存在，请刷新列表")
	}
	selection := append([]string{}, ids...)
	sort.Strings(selection)
	plan, _ := json.Marshal(selection)
	digest := sha256.Sum256(append(append(current, 0), plan...))
	v.Revision = hex.EncodeToString(digest[:])
	if !apply {
		return v, nil
	}
	if expected == "" || expected != v.Revision {
		return v, errors.New("订阅列表或设置已变化，请重新预览后确认")
	}
	for _, p := range targets {
		for {
			token, e := randomToken(25)
			if e != nil {
				return v, e
			}
			if used[token] {
				continue
			}
			used[token] = true
			p["slug"] = token
			p["customSlug"] = false
			break
		}
	}
	// Keep an owner-readable index backup before committing the single atomic file.
	// A failure to create or sync the backup must not rotate any capability.
	dir := filepath.Join(r.Root, "subscription-rotation-backups")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return v, errors.New("无法创建订阅链接轮换备份目录")
	}
	f, err := os.CreateTemp(dir, "profiles-"+time.Now().UTC().Format("20060102T150405Z")+"-*.json")
	if err != nil {
		return v, errors.New("无法创建订阅链接轮换备份")
	}
	backup := f.Name()
	saved := false
	defer func() {
		if !saved {
			os.Remove(backup)
		}
	}()
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(current)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil || closeErr != nil {
		return v, errors.New("订阅索引备份写入失败，未轮换链接")
	}
	saved = true
	if err = r.writeIndex(index); err != nil {
		return v, err
	}
	v.Backup = filepath.Base(backup)
	return v, nil
}
