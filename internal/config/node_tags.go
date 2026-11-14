package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

const NodeTagsKey = "x-mxioc-tags"

func nodeTags(value any) ([]string, error) {
	if value == nil {
		return []string{}, nil
	}
	list, ok := value.([]any)
	if !ok || len(list) > 16 {
		return nil, errors.New("节点标签须为最多 16 个字符串的列表")
	}
	result := []string{}
	seen := map[string]bool{}
	for _, v := range list {
		s, ok := v.(string)
		if !ok || !utf8.ValidString(s) || strings.TrimSpace(s) != s || s == "" || utf8.RuneCountInString(s) > 32 || strings.ContainsFunc(s, unicode.IsControl) {
			return nil, errors.New("每个节点标签须为 1–32 个字符，不含首尾空白或控制字符")
		}
		if seen[s] {
			return nil, errors.New("节点标签不能重复")
		}
		seen[s] = true
		result = append(result, s)
	}
	return result, nil
}
func tagsValue(tags []string) []any {
	v := make([]any, len(tags))
	for i, s := range tags {
		v[i] = s
	}
	return v
}

type NodeTagsChange struct {
	Name   string   `json:"name"`
	Before []string `json:"before"`
	After  []string `json:"after"`
}
type NodeTagsReview struct {
	Changes   []NodeTagsChange `json:"changes"`
	Unchanged int              `json:"unchanged"`
	Revision  string           `json:"revision"`
}

func (r *Repository) ReviewNodeTags(id string, names []string, mode string, tags []string, expected string, apply bool) (NodeTagsReview, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	v := NodeTagsReview{Changes: []NodeTagsChange{}}
	if len(names) == 0 || len(names) > 500 {
		return v, errors.New("请选择 1–500 个节点")
	}
	if mode != "add" && mode != "remove" && mode != "replace" && mode != "clear" {
		return v, errors.New("标签操作无效")
	}
	if mode == "clear" && len(tags) != 0 || mode != "clear" && len(tags) == 0 {
		return v, errors.New("清空操作不接收标签，其他操作至少填写一个标签")
	}
	if _, err := nodeTags(tagsValue(tags)); err != nil {
		return v, err
	}
	selected := map[string]bool{}
	for _, name := range names {
		if name == "" || len(name) > 1024 || selected[name] {
			return v, errors.New("节点选择无效或重复")
		}
		selected[name] = true
	}
	p, err := r.profile(id)
	if err != nil {
		return v, err
	}
	doc, raw, err := r.cachedRead(p)
	if err != nil {
		return v, err
	}
	for _, item := range rows(doc, "proxies") {
		n := item.(Document)
		name := stringValue(n["name"])
		if !selected[name] {
			continue
		}
		delete(selected, name)
		before, err := nodeTags(n[NodeTagsKey])
		if err != nil {
			return v, err
		}
		after := append([]string{}, before...)
		wanted := map[string]bool{}
		for _, tag := range tags {
			wanted[tag] = true
		}
		switch mode {
		case "clear":
			after = []string{}
		case "replace":
			after = append([]string{}, tags...)
		case "remove":
			after = []string{}
			for _, tag := range before {
				if !wanted[tag] {
					after = append(after, tag)
				}
			}
		case "add":
			present := map[string]bool{}
			for _, tag := range before {
				present[tag] = true
			}
			for _, tag := range tags {
				if !present[tag] {
					after = append(after, tag)
				}
			}
		}
		if len(after) > 16 {
			return v, errors.New("操作后单个节点超过 16 个标签，未保存任何修改")
		}
		if equalConfig(tagsValue(before), tagsValue(after)) {
			v.Unchanged++
		} else {
			v.Changes = append(v.Changes, NodeTagsChange{Name: name, Before: before, After: after})
		}
	}
	if len(selected) > 0 {
		return v, errors.New("所选节点已不存在，请刷新后重新选择")
	}
	selection := append([]string{}, names...)
	sort.Strings(selection)
	plan, _ := json.Marshal(struct {
		Names []string
		Mode  string
		Tags  []string
	}{selection, mode, tags})
	digest := sha256.Sum256(append([]byte(reviewedRevision(p, raw)+"\x00"), plan...))
	v.Revision = hex.EncodeToString(digest[:])
	if apply {
		if expected == "" || expected != v.Revision {
			return v, errors.New("订阅配置或标签操作已变化，请重新预览")
		}
		err = r.mutateLocked(id, func(d Document) error {
			changes := map[string][]string{}
			for _, change := range v.Changes {
				changes[change.Name] = change.After
			}
			for _, item := range rows(d, "proxies") {
				n := item.(Document)
				if tags, ok := changes[stringValue(n["name"])]; ok {
					if len(tags) == 0 {
						delete(n, NodeTagsKey)
					} else {
						n[NodeTagsKey] = tagsValue(tags)
					}
				}
			}
			return nil
		})
	}
	return v, err
}

// Keep management metadata out of raw subscriptions and every conversion source.
// The cached document is immutable: clone only if a metadata key is present.
func stripNodeTags(doc Document) (Document, bool) {
	for _, item := range rows(doc, "proxies") {
		if _, ok := item.(Document)[NodeTagsKey]; ok {
			next := cloneConfig(doc).(Document)
			for _, item := range rows(next, "proxies") {
				delete(item.(Document), NodeTagsKey)
			}
			return next, true
		}
	}
	return doc, false
}
