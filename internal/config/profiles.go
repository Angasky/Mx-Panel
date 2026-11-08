package config

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

var slugPattern = regexp.MustCompile(`^[a-zA-Z0-9_-]{32,80}$`)

func randomToken(size int) (string, error) {
	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return "", err
	}
	return hex.EncodeToString(data), nil
}

// index returns an owned document; cache contents never escape to mutations.
func (r *Repository) index() (map[string]any, error) {
	entry, _, err := r.indexEntry()
	if err != nil {
		return nil, err
	}
	return cloneConfig(entry.document).(Document), nil
}

func (r *Repository) indexEntry() (*profileIndexEntry, []byte, error) {
	data, err := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
	if err != nil {
		r.profileCache = nil
		return nil, nil, errors.New("订阅索引读取失败")
	}
	digest := sha256.Sum256(data)
	if r.profileCache != nil && r.profileCache.digest == digest {
		return r.profileCache, data, nil
	}
	r.profileCache = nil
	index, err := parseProfileIndex(data)
	if err != nil {
		return nil, nil, err
	}
	entry := &profileIndexEntry{digest: digest, document: index}
	// Oversized indexes remain supported but are not retained in memory.
	if len(data) <= 1<<20 {
		r.profileCache = entry
	}
	return entry, data, nil
}

func parseProfileIndex(data []byte) (Document, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var index map[string]any
	if decoder.Decode(&index) != nil || index == nil || decoder.Decode(new(any)) != io.EOF {
		return nil, errors.New("订阅索引格式无效")
	}
	if _, ok := index["profiles"].([]any); !ok {
		return nil, errors.New("订阅索引格式无效")
	}
	if value := index["policyTemplates"]; value != nil {
		templates, ok := value.([]any)
		if !ok {
			return nil, errors.New("策略模板列表格式无效")
		}
		seen := map[string]bool{}
		for _, item := range templates {
			record, ok := item.(map[string]any)
			if !ok {
				return nil, errors.New("策略模板记录格式无效")
			}
			id := stringValue(record["id"])
			if strings.TrimSpace(id) == "" || seen[id] {
				return nil, errors.New("策略模板 ID 无效或重复")
			}
			seen[id] = true
		}
	}
	identities := map[string]bool{}
	for _, value := range index["profiles"].([]any) {
		record, ok := value.(map[string]any)
		if !ok {
			return nil, errors.New("订阅索引记录格式无效")
		}
		id := stringValue(record["id"])
		if id != "" {
			if identities[id] {
				return nil, errors.New("订阅 ID 重复，请先修复索引")
			}
			identities[id] = true
		}
		if value, present := record["remoteNodes"]; present && value != nil {
			bindings, ok := value.([]any)
			if !ok {
				return nil, errors.New("订阅绑定列表格式无效")
			}
			for _, binding := range bindings {
				if _, ok := binding.(map[string]any); !ok {
					return nil, errors.New("订阅绑定记录格式无效")
				}
			}
		}
	}
	return index, nil
}

// MigrateLegacyProfiles runs before serving requests, never as a side effect of
// a rejected mutation. The caller must not have started background workers.
func (r *Repository) MigrateLegacyProfiles() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	changed := false
	used := map[string]bool{}
	for _, value := range index["profiles"].([]any) {
		record := value.(map[string]any)
		used[stringValue(record["slug"])] = true
	}
	for _, value := range index["profiles"].([]any) {
		record := value.(map[string]any)
		slug := stringValue(record["slug"])
		if slug == "" || record["customSlug"] == true && len(slug) < 32 {
			for {
				candidate, err := randomToken(25)
				if err != nil {
					return err
				}
				if !used[candidate] {
					record["slug"], record["customSlug"] = candidate, false
					used[candidate] = true
					changed = true
					break
				}
			}
		}
		bindings, _ := record["remoteNodes"].([]any)
		for _, value := range bindings {
			binding := value.(map[string]any)
			if binding["status"] == "active" && strings.HasPrefix(stringValue(binding["error"]), "远端入站身份已变化，已停止自动删除") {
				binding["status"] = "identity_changed"
				if _, exists := binding["invalidatedAt"]; !exists {
					binding["invalidatedAt"] = time.Now().Unix()
				}
				changed = true
			}
		}
	}
	if changed {
		if err := r.writeIndex(index); err != nil {
			return err
		}
	}
	return nil
}
func (r *Repository) writeIndex(index map[string]any) error {
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return atomic(filepath.Join(r.Root, "profiles.json"), append(data, '\n'))
}
func hasActiveBindings(record map[string]any) bool {
	bindings, _ := record["remoteNodes"].([]any)
	for _, value := range bindings {
		if binding, ok := value.(map[string]any); ok && (binding["status"] == "active" || binding["status"] == "provisioning") {
			return true
		}
	}
	return false
}
func profileFrom(record map[string]any) (Profile, error) {
	data, err := json.Marshal(record)
	if err != nil {
		return Profile{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var p Profile
	err = decoder.Decode(&p)
	return p, err
}

func (r *Repository) CreateProfile(payload map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := strings.TrimSpace(stringValue(payload["name"]))
	if name == "" || len(name) > 300 || strings.ContainsAny(name, "\r\n\x00") {
		return nil, errors.New("订阅名称无效")
	}
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	records := index["profiles"].([]any)
	slug := stringValue(payload["slug"])
	custom := payload["customSlug"] == true
	if custom {
		if !slugPattern.MatchString(slug) {
			return nil, errors.New("订阅标识必须为 32–80 位字母、数字、横线或下划线")
		}
	} else {
		slug, err = randomToken(25)
		if err != nil {
			return nil, err
		}
	}
	for _, value := range records {
		if value.(map[string]any)["slug"] == slug {
			return nil, errors.New("订阅链接标识已经存在")
		}
	}
	id, err := randomToken(12)
	if err != nil {
		return nil, err
	}
	id = "p-" + id
	template := stringValue(payload["templateId"])
	if template == "" {
		template = "blank"
	}
	var doc Document
	if strings.HasPrefix(template, "policy-") {
		var selected Document
		for _, item := range rows(index, "policyTemplates") {
			if candidate, ok := item.(Document); ok && candidate["id"] == template {
				selected = candidate
				break
			}
		}
		if selected == nil {
			return nil, errors.New("策略模板不存在，请重新选择")
		}
		doc, err = r.blankProfile()
		if err != nil {
			return nil, err
		}
		if err = normalizeNumbers(selected); err != nil {
			return nil, err
		}
		if err = applyPolicyTemplate(doc, selected); err != nil {
			return nil, err
		}
	} else if template != "blank" {
		var source map[string]any
		for _, value := range records {
			record := value.(map[string]any)
			if record["id"] == template {
				source = record
				break
			}
		}
		if source == nil {
			return nil, errors.New("模板订阅不存在")
		}
		if hasActiveBindings(source) {
			return nil, errors.New("模板拥有服务器专属用户，不能复制凭证供其他订阅共用")
		}
		p, err := profileFrom(source)
		if err != nil {
			return nil, err
		}
		doc, _, err = r.cachedRead(p)
		if err == nil {
			doc = cloneConfig(doc).(Document)
		}
		if err != nil {
			return nil, err
		}
	} else {
		doc, err = r.blankProfile()
		if err != nil {
			return nil, err
		}
	}
	if err = validate(doc); err != nil {
		return nil, err
	}
	if err = checkReferences(doc); err != nil {
		return nil, err
	}
	data, err := yaml.Marshal(doc)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(r.Root, "profiles")
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, id+".yaml")
	if err = atomic(path, data); err != nil {
		return nil, err
	}
	record := map[string]any{"id": id, "name": name, "slug": slug, "customSlug": custom, "protected": false, "files": []any{path}}
	index["profiles"] = append(records, record)
	if err = r.writeIndex(index); err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	p, err := profileFrom(record)
	if err != nil {
		return nil, err
	}
	return public(p), nil
}

func (r *Repository) UpdateProfile(payload map[string]any) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	id := stringValue(payload["oldId"])
	var record map[string]any
	records := index["profiles"].([]any)
	for _, value := range records {
		row := value.(map[string]any)
		if row["id"] == id {
			record = row
			break
		}
	}
	if record == nil {
		return nil, errors.New("订阅配置不存在")
	}
	name := strings.TrimSpace(stringValue(payload["name"]))
	if name == "" || len(name) > 300 || strings.ContainsAny(name, "\r\n\x00") {
		return nil, errors.New("订阅名称无效")
	}
	custom := payload["customSlug"] == true
	slug := stringValue(record["slug"])
	if custom {
		slug = stringValue(payload["slug"])
		if !slugPattern.MatchString(slug) {
			return nil, errors.New("订阅标识必须为 32–80 位字母、数字、横线或下划线")
		}
	} else if record["customSlug"] == true || slug == "" {
		slug, err = randomToken(25)
		if err != nil {
			return nil, err
		}
	}
	for _, value := range records {
		row := value.(map[string]any)
		if row["id"] != id && row["slug"] == slug {
			return nil, errors.New("订阅链接标识已经存在")
		}
	}
	record["name"] = name
	record["slug"] = slug
	record["customSlug"] = custom
	p, err := profileFrom(record)
	if err != nil {
		return nil, err
	}
	if err = r.writeIndex(index); err != nil {
		return nil, err
	}
	return public(p), nil
}

func (r *Repository) DeleteProfile(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	records := index["profiles"].([]any)
	var record map[string]any
	next := []any{}
	for _, value := range records {
		row := value.(map[string]any)
		if row["id"] == id {
			record = row
		} else {
			next = append(next, row)
		}
	}
	if record == nil {
		return errors.New("订阅不存在")
	}
	if record["protected"] == true {
		return errors.New("主订阅不能删除")
	}
	if hasActiveBindings(record) {
		return errors.New("订阅仍拥有服务器节点，不能丢弃计费关联")
	}
	p, err := profileFrom(record)
	if err != nil {
		return err
	}
	// Remove the public index entry first; a file cleanup failure must not leave
	// a publicly addressable subscription with partially deleted configuration.
	index["profiles"] = next
	if err = r.writeIndex(index); err != nil {
		return err
	}
	for _, path := range p.Files {
		// Only generated profile files are eligible for automatic cleanup. Legacy
		// external paths are retained rather than allowing index-driven deletion.
		relative, err := filepath.Rel(filepath.Join(r.Root, "profiles"), path)
		if err == nil && relative != "." && !strings.HasPrefix(relative, "..") && !filepath.IsAbs(relative) {
			if err = os.Remove(path); err != nil && !os.IsNotExist(err) {
				return errors.New("订阅已移除，配置文件需手动清理")
			}
		}
	}
	return nil
}
