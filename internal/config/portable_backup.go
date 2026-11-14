package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Portable backups intentionally contain only the subscription YAML. No paths,
// login credentials, remote bindings, quotas or public subscription tokens.
type PortableBackup struct {
	Format  string `json:"format"`
	Version int    `json:"version"`
	Name    string `json:"name"`
	Created string `json:"created"`
	YAML    string `json:"yaml"`
}
type PortablePreview struct {
	Name     string `json:"name"`
	Created  string `json:"created"`
	Target   string `json:"target"`
	Nodes    int    `json:"nodes"`
	Groups   int    `json:"groups"`
	Rules    int    `json:"rules"`
	Revision string `json:"revision"`
}

func (r *Repository) ExportPortable(id string, now time.Time) (PortableBackup, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, e := r.profile(id)
	if e != nil {
		return PortableBackup{}, e
	}
	_, raw, e := r.cachedRead(p)
	if e != nil {
		return PortableBackup{}, e
	}
	if len(raw) > 768<<10 {
		return PortableBackup{}, errors.New("可移植备份当前支持最多 768 KiB 的订阅 YAML")
	}
	return PortableBackup{Format: "mx-panel-subscription", Version: 1, Name: p.Name, Created: now.UTC().Format(time.RFC3339), YAML: string(raw)}, nil
}
func (r *Repository) ReviewPortable(id string, b PortableBackup, expected string, apply bool) (PortablePreview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := PortablePreview{}
	if b.Format != "mx-panel-subscription" || b.Version != 1 || len(b.YAML) > 768<<10 || len(b.Name) > 512 || !utf8.ValidString(b.Name) || strings.ContainsFunc(b.Name, unicode.IsControl) {
		return v, errors.New("不支持的备份内容或格式版本")
	}
	if _, e := time.Parse(time.RFC3339, b.Created); e != nil {
		return v, errors.New("备份时间格式无效")
	}
	next := Document{}
	if e := ReplaceRaw(next, Document{"yaml": b.YAML}); e != nil {
		return v, errors.New("备份中的 YAML 或引用关系无效")
	}
	p, e := r.profile(id)
	if e != nil {
		return v, e
	}
	original, raw, e := r.cachedRead(p)
	if e != nil {
		return v, e
	}
	if protectedComponents(original, p) != protectedComponents(next, p) {
		return v, errors.New("恢复会改变主备链路引用的节点或策略组，请先处理对应主备组")
	}
	packed, _ := json.Marshal(b)
	h := sha256.New()
	fmt.Fprint(h, reviewedRevision(p, raw))
	h.Write(packed)
	v = PortablePreview{Name: b.Name, Created: b.Created, Target: p.Name, Nodes: len(rows(next, "proxies")), Groups: len(rows(next, "proxy-groups")), Rules: len(rows(next, "rules")), Revision: hex.EncodeToString(h.Sum(nil))}
	if apply {
		if expected == "" || expected != v.Revision {
			return v, errors.New("当前订阅或备份已改变，请重新预览后确认恢复")
		}
		e = r.mutateLocked(id, func(d Document) error { return ReplaceRaw(d, Document{"yaml": b.YAML}) })
	}
	return v, e
}
