package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
)

// CertificateReview contains names only, never node credentials or addresses.
type CertificateReview struct {
	Changed   []string `json:"changed"`
	Unchanged []string `json:"unchanged"`
	Revision  string   `json:"revision"`
}

// ReviewNodeCertificates binds confirmation to both the selection and profile
// contents. Every selected node is resolved before one guarded transaction.
func (r *Repository) ReviewNodeCertificates(id string, names []string, expected string, apply bool) (CertificateReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := CertificateReview{Changed: []string{}, Unchanged: []string{}}
	if len(names) == 0 || len(names) > 500 {
		return v, errors.New("请选择 1–500 个节点")
	}
	selected := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 1024 || selected[name] {
			return v, errors.New("节点名称为空、过长或重复")
		}
		selected[name] = true
	}
	p, err := r.profile(id)
	if err != nil {
		return v, err
	}
	original, raw, err := r.cachedRead(p)
	if err != nil {
		return v, err
	}
	next := cloneConfig(original).(Document)
	for _, item := range rows(next, "proxies") {
		n := item.(Document)
		name := stringValue(n["name"])
		if !selected[name] {
			continue
		}
		delete(selected, name)
		value, exists := n["skip-cert-verify"]
		if exists {
			if _, ok := value.(bool); !ok {
				return v, errors.New("节点证书验证字段不是布尔值，请先在节点编辑器修正")
			}
		}
		if value == true {
			n["skip-cert-verify"] = false
			v.Changed = append(v.Changed, name)
		} else {
			v.Unchanged = append(v.Unchanged, name)
		}
	}
	if len(selected) > 0 {
		return v, errors.New("所选节点已不存在，请刷新后重新选择")
	}
	if protectedComponents(original, p) != protectedComponents(next, p) {
		return v, errors.New("所选节点被主备链路保护，请先调整对应主备组")
	}
	selection := append([]string(nil), names...)
	sort.Strings(selection)
	packed, _ := json.Marshal(selection)
	digest := sha256.Sum256(append([]byte(reviewedRevision(p, raw)+"\x00"), packed...))
	v.Revision = hex.EncodeToString(digest[:])
	if apply {
		if expected == "" || expected != v.Revision {
			return v, errors.New("订阅配置或节点选择已变化，请重新预览")
		}
		err = r.mutateLocked(id, func(doc Document) error {
			targets := map[string]bool{}
			for _, name := range v.Changed {
				targets[name] = true
			}
			for _, item := range rows(doc, "proxies") {
				n := item.(Document)
				if targets[stringValue(n["name"])] {
					n["skip-cert-verify"] = false
				}
			}
			return nil
		})
	}
	return v, err
}
