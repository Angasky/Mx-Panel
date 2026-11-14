package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
)

// ReviewedEdit is a bounded, native configuration operation, never shell code.
type ReviewedEdit struct {
	Resource string   `json:"resource"`
	Method   string   `json:"method"`
	Payload  Document `json:"payload"`
}

func reviewedRevision(p Profile, raw []byte) string {
	binding, _ := json.Marshal(p)
	h := sha256.New()
	h.Write(binding)
	h.Write([]byte{0})
	h.Write(raw)
	return hex.EncodeToString(h.Sum(nil))
}

// AssistantSnapshot exposes references needed for editing, but no node addresses,
// credentials, provider URLs, or arbitrary extension fields.
func (r *Repository) AssistantSnapshot(id string) (Document, string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, "", err
	}
	doc, raw, err := r.cachedRead(p)
	if err != nil {
		return nil, "", err
	}
	result := Document{"nodes": []any{}, "groups": []any{}, "rules": cloneConfig(rows(doc, "rules")), "dnsDomains": []any{}}
	for _, item := range rows(doc, "proxies") {
		n := item.(Document)
		result["nodes"] = append(result["nodes"].([]any), Document{"name": n["name"], "type": n["type"]})
	}
	for _, item := range rows(doc, "proxy-groups") {
		n := item.(Document)
		g := Document{}
		for _, k := range []string{"name", "type", "proxies", "use", "interval", "tolerance", "strategy"} {
			if v, ok := n[k]; ok {
				g[k] = cloneConfig(v)
			}
		}
		result["groups"] = append(result["groups"].([]any), g)
	}
	if dns, ok := doc["dns"].(Document); ok {
		if policies, ok := dns["nameserver-policy"].(Document); ok {
			for name := range policies {
				result["dnsDomains"] = append(result["dnsDomains"].([]any), name)
			}
		}
	}
	return result, reviewedRevision(p, raw), nil
}

func applyReviewedEdits(doc Document, edits []ReviewedEdit) error {
	if len(edits) == 0 || len(edits) > 20 {
		return errors.New("一次配置计划须包含 1–20 项修改")
	}
	for i, edit := range edits {
		if edit.Method != "POST" && edit.Method != "PUT" && edit.Method != "DELETE" {
			return errors.New("配置修改方法无效")
		}
		payload := cloneConfig(edit.Payload)
		p, ok := payload.(Document)
		if !ok || p == nil {
			return errors.New("配置修改参数必须为对象")
		}
		var err error
		switch edit.Resource {
		case "groups":
			err = EditGroup(doc, edit.Method, p)
		case "rules":
			err = EditRule(doc, edit.Method, p)
		case "dns":
			err = EditDNS(doc, edit.Method, p)
		case "node_patch":
			if edit.Method != "PUT" {
				return errors.New("已有节点只支持安全字段修改")
			}
			patch, ok := p["config"].(Document)
			if !ok || len(patch) == 0 {
				return errors.New("节点修改字段为空")
			}
			for key := range patch {
				switch key {
				case "name", "port", "sni", "servername", "tls", "skip-cert-verify", "udp", "network", "client-fingerprint", "alpn":
				default:
					return fmt.Errorf("不支持修改节点字段 %s；地址、凭据和扩展配置请在节点编辑器修改", key)
				}
			}
			found := false
			for _, item := range rows(doc, "proxies") {
				old := item.(Document)
				if old["name"] != p["oldName"] {
					continue
				}
				next := cloneConfig(old).(Document)
				for key, v := range patch {
					next[key] = v
				}
				err = EditNode(doc, "PUT", Document{"oldName": p["oldName"], "config": next})
				found = true
				break
			}
			if !found {
				err = errors.New("原节点不存在")
			}
		default:
			return errors.New("不支持的配置资源")
		}
		if err != nil {
			return fmt.Errorf("第 %d 项修改无效：%w", i+1, err)
		}
	}
	if err := validate(doc); err != nil {
		return err
	}
	return checkReferences(doc)
}

// ReviewEdits previews or commits under the repository lock, binding the plan to
// both configuration contents and profile metadata. Mutate supplies backups and
// atomic mirror replacement. A stale plan cannot overwrite intervening changes.
func (r *Repository) ReviewEdits(id, revision string, edits []ReviewedEdit, commit bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return err
	}
	original, raw, err := r.cachedRead(p)
	if err != nil {
		return err
	}
	if revision == "" || reviewedRevision(p, raw) != revision {
		return errors.New("订阅配置已变化，请重新分析并生成计划")
	}
	next := cloneConfig(original).(Document)
	if err = applyReviewedEdits(next, edits); err != nil {
		return err
	}
	if protectedComponents(original, p) != protectedComponents(next, p) {
		return errors.New("节点或策略组被主备链路引用，请先调整对应主备组")
	}
	if !commit {
		return nil
	}
	return r.mutateLocked(id, func(doc Document) error { return applyReviewedEdits(doc, edits) })
}
