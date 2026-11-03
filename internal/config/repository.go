package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"go.yaml.in/yaml/v3"
)

type Repository struct {
	Root       string
	mu         sync.Mutex
	cache      map[string]*configEntry
	cacheBytes int
	cacheClock uint64
}
type Profile struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Slug             string           `json:"slug"`
	Protected        bool             `json:"protected"`
	CustomSlug       bool             `json:"customSlug"`
	Files            []string         `json:"files"`
	Traffic          map[string]any   `json:"traffic"`
	Failovers        []map[string]any `json:"failovers"`
	RemoteNodes      []any            `json:"remoteNodes"`
	AccessRevoked    bool             `json:"accessRevoked"`
	EnforcementError string           `json:"enforcementError"`
	LastEnforcedAt   any              `json:"lastEnforcedAt"`
	Plans            []Document       `json:"-"`
}
type Document = map[string]any

func (r *Repository) profiles() ([]Profile, error) {
	data, err := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
	if err != nil {
		return nil, errors.New("订阅索引读取失败")
	}
	var index struct {
		Profiles          []Profile       `json:"profiles"`
		SubscriptionPlans json.RawMessage `json:"subscriptionPlans"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if decoder.Decode(&index) != nil || index.Profiles == nil {
		return nil, errors.New("订阅索引格式无效")
	}
	planIndex := Document{}
	if len(index.SubscriptionPlans) > 0 {
		var list any
		d := json.NewDecoder(strings.NewReader(string(index.SubscriptionPlans)))
		d.UseNumber()
		if d.Decode(&list) != nil {
			return nil, errors.New("套餐模板列表格式无效")
		}
		planIndex["subscriptionPlans"] = list
	}
	plans, err := plansFrom(planIndex)
	if err != nil {
		return nil, err
	}
	for i := range index.Profiles {
		index.Profiles[i].Plans = plans
	}
	return index.Profiles, nil
}
func public(p Profile) map[string]any {
	info, err := TrafficInfo(Document{"id": p.ID, "traffic": p.Traffic, "remoteNodes": p.RemoteNodes, "accessRevoked": p.AccessRevoked, "enforcementError": p.EnforcementError, "lastEnforcedAt": p.LastEnforcedAt}, time.Now())
	if err != nil {
		info = Document{"configured": false, "enforcementError": err.Error(), "bindings": []any{}}
	}
	if p.Plans == nil {
		p.Plans, _ = plansFrom(Document{})
	}
	info["plans"] = p.Plans
	return map[string]any{"id": p.ID, "name": p.Name, "slug": p.Slug, "protected": p.Protected, "customSlug": p.CustomSlug, "url": "/sub/" + url.PathEscape(p.Slug), "traffic": info}
}
func (r *Repository) Profiles() ([]map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	profiles, err := r.profiles()
	if err != nil {
		return nil, err
	}
	result := make([]map[string]any, 0, len(profiles))
	for _, p := range profiles {
		result = append(result, public(p))
	}
	return result, nil
}
func (r *Repository) profile(id string) (Profile, error) {
	rows, err := r.profiles()
	if err != nil {
		return Profile{}, err
	}
	if id == "" {
		id = "clash"
	}
	for _, p := range rows {
		if p.ID == id && len(p.Files) > 0 {
			return p, nil
		}
	}
	return Profile{}, errors.New("所选订阅配置不存在")
}
func read(p Profile) (Document, []byte, error) {
	f, err := os.Open(p.Files[0])
	if err != nil {
		return nil, nil, errors.New("订阅配置读取失败")
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 8<<20+1))
	if err != nil || len(raw) > 8<<20 {
		return nil, nil, errors.New("订阅配置超过限制")
	}
	return parseConfig(raw)
}
func parseConfig(raw []byte) (Document, []byte, error) {
	var err error
	var doc Document
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	if err = decoder.Decode(&doc); err != nil || doc == nil {
		return nil, nil, errors.New("订阅 YAML 格式无效")
	}
	var extra any
	if err = decoder.Decode(&extra); err != io.EOF {
		return nil, nil, errors.New("不支持多个 YAML 文档")
	}
	if err = validate(doc); err != nil {
		return nil, nil, err
	}
	return doc, raw, nil
}
func rows(doc Document, key string) []any {
	value, _ := doc[key].([]any)
	if value == nil {
		return []any{}
	}
	return value
}
func validate(doc Document) error {
	names := map[string]bool{}
	for _, key := range []string{"proxies", "proxy-groups"} {
		if doc[key] == nil {
			continue
		}
		list, ok := doc[key].([]any)
		if !ok {
			return fmt.Errorf("%s 必须是列表", key)
		}
		for _, item := range list {
			row, ok := item.(map[string]any)
			if !ok {
				return errors.New("节点或策略组格式无效")
			}
			name, ok := row["name"].(string)
			if !ok || strings.TrimSpace(name) == "" || names[name] {
				return errors.New("节点或策略组名称为空或重复")
			}
			names[name] = true
		}
	}
	if doc["rules"] != nil {
		if _, ok := doc["rules"].([]any); !ok {
			return errors.New("规则必须为列表")
		}
		for _, v := range rows(doc, "rules") {
			if _, ok := v.(string); !ok {
				return errors.New("规则必须为字符串")
			}
		}
	}
	return nil
}
func (r *Repository) Raw(id string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return "", err
	}
	_, raw, err := r.cachedRead(p)
	return string(raw), err
}
func (r *Repository) Snapshot(id string) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	doc, _, err := r.cachedRead(p)
	if err != nil {
		return nil, err
	}
	base := snapshotBase(cloneConfig(doc).(Document))
	info, _ := os.Stat(p.Files[0])
	updated := ""
	if info != nil {
		updated = info.ModTime().Format("2006-01-02 15:04:05")
	}
	base["profile"] = public(p)
	base["updated"] = updated
	return base, nil
}

func snapshotBase(doc Document) Document {
	nodes := []any{}
	groups := []any{}
	rules := []any{}
	policies := []any{}
	for i, v := range rows(doc, "proxies") {
		n := v.(map[string]any)
		port := n["port"]
		if n["port-range"] != nil {
			port = n["port-range"]
		}
		nodes = append(nodes, map[string]any{"index": i, "name": n["name"], "type": n["type"], "server": n["server"], "port": port, "config": n})
	}
	for i, v := range rows(doc, "proxy-groups") {
		g := v.(map[string]any)
		refs, _ := g["proxies"].([]any)
		groups = append(groups, map[string]any{"index": i, "name": g["name"], "type": g["type"], "count": len(refs), "config": g})
	}
	for i, v := range rows(doc, "rules") {
		item := RuleParts(v.(string))
		item["index"] = i
		rules = append(rules, item)
	}
	if dns, ok := doc["dns"].(map[string]any); ok {
		if policy, ok := dns["nameserver-policy"].(map[string]any); ok {
			for domain, value := range policy {
				servers, ok := value.([]any)
				if !ok {
					servers = []any{value}
				}
				policies = append(policies, map[string]any{"domain": domain, "servers": servers})
			}
		}
	}
	return Document{"nodes": nodes, "groups": groups, "rules": rules, "dnsPolicies": policies}
}

func atomic(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".mxioc-go-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}

// Mutate keeps reads and all mirrored writes under one profile repository lock.
// A failed mirror write restores earlier files, with explicit rollback errors.
func (r *Repository) Mutate(id string, change func(Document) error) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.mutateLocked(id, change)
}

func (r *Repository) mutateLocked(id string, change func(Document) error) error {
	p, err := r.profile(id)
	if err != nil {
		return err
	}
	original, raw, err := r.cachedRead(p)
	if err != nil {
		return err
	}
	doc := cloneConfig(original).(Document)
	protected := protectedComponents(doc, p)
	if err = change(doc); err != nil {
		return err
	}
	if err = validate(doc); err != nil {
		return err
	}
	if protected != protectedComponents(doc, p) {
		return errors.New("节点或策略组被主备链路引用，请先删除对应主备组")
	}
	unchanged := equalConfig(original, doc)
	next := raw
	if !unchanged {
		next, err = yaml.Marshal(doc)
		if err != nil {
			return errors.New("配置序列化失败")
		}
	}
	originals := make([][]byte, len(p.Files))
	exists := make([]bool, len(p.Files))
	for i, file := range p.Files {
		originals[i], err = os.ReadFile(file)
		exists[i] = err == nil
		if err != nil && !os.IsNotExist(err) {
			return errors.New("配置镜像读取失败")
		}
	}
	if unchanged {
		healthy := true
		for i := range originals {
			if !exists[i] || !bytes.Equal(originals[i], raw) {
				healthy = false
				break
			}
		}
		if healthy {
			return nil
		}
	}
	// Publish only after every mirror is durable. Failure/rollback must discard
	// derived data; never cache a callback's mutable document by reference.
	committed := false
	defer func() {
		r.invalidateConfig(p.Files[0])
		if committed {
			r.rememberCommitted(p.Files[0], next, doc)
		}
	}()
	backupDir := filepath.Join(r.Root, "backups")
	if !regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`).MatchString(p.ID) {
		return errors.New("订阅 ID 不适合生成备份")
	}
	if err = os.MkdirAll(backupDir, 0700); err != nil {
		return err
	}
	// The backup filename does not interpolate user-provided profile identifiers.
	backup, err := os.CreateTemp(backupDir, p.ID+"."+time.Now().UTC().Format("20060102T150405")+".*.yaml")
	if err != nil {
		return err
	}
	if err = backup.Chmod(0600); err == nil {
		_, err = backup.Write(originals[0])
	}
	if err == nil {
		err = backup.Sync()
	}
	closeErr := backup.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	for i, file := range p.Files {
		if err = atomic(file, next); err != nil {
			var rollback []error
			for j := i - 1; j >= 0; j-- {
				if exists[j] {
					rollback = append(rollback, atomic(p.Files[j], originals[j]))
				} else {
					rollback = append(rollback, os.Remove(p.Files[j]))
				}
			}
			return errors.Join(append([]error{errors.New("配置写入失败，已尝试恢复原文件")}, rollback...)...)
		}
	}
	committed = true
	return nil
}

func protectedComponents(doc Document, p Profile) string {
	names := map[string]bool{}
	for _, row := range p.Failovers {
		for _, key := range []string{"name", "exit"} {
			if value, ok := row[key].(string); ok {
				names[value] = true
			}
		}
		for _, key := range []string{"entries", "paths"} {
			if values, ok := row[key].([]any); ok {
				for _, value := range values {
					if name, ok := value.(string); ok {
						names[name] = true
					}
				}
			}
		}
	}
	selected := map[string]any{}
	for _, key := range []string{"proxies", "proxy-groups"} {
		for _, value := range rows(doc, key) {
			row := value.(map[string]any)
			if names[stringValue(row["name"])] {
				selected[key+":"+stringValue(row["name"])] = row
			}
		}
	}
	data, _ := json.Marshal(selected)
	return string(data)
}
