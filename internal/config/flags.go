package config

import (
	"errors"
	"strings"
	"unicode"

	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

type FlagTarget struct{ Name, Server, Identity string }
type FlagCountry struct{ Code, IP, Error string }

func (r *Repository) FlagTargets(id string, input any) ([]FlagTarget, error) {
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
	selected := map[string]bool{}
	if input != nil {
		names, ok := input.([]any)
		if !ok {
			return nil, errors.New("节点选择格式不正确")
		}
		for _, v := range names {
			name, ok := v.(string)
			if !ok {
				return nil, errors.New("节点选择格式不正确")
			}
			if strings.TrimSpace(name) != "" {
				selected[name] = true
			}
		}
	}
	blocked := map[string]bool{}
	for _, f := range p.Failovers {
		for _, key := range []string{"name", "exit"} {
			blocked[stringValue(f[key])] = true
		}
		for _, key := range []string{"paths", "entries"} {
			for _, v := range rows(f, key) {
				blocked[stringValue(v)] = true
			}
		}
	}
	result := []FlagTarget{}
	for _, v := range rows(doc, "proxies") {
		n := v.(map[string]any)
		name := stringValue(n["name"])
		if !blocked[name] && (len(selected) == 0 || selected[name]) {
			result = append(result, FlagTarget{name, stringValue(n["server"]), managednodes.Identity(n)})
		}
	}
	if len(result) == 0 {
		return nil, errors.New("没有可处理的节点")
	}
	return result, nil
}
func countryName(name, code string) string {
	runes := []rune(name)
	for len(runes) >= 2 && runes[0] >= 0x1f1e6 && runes[0] <= 0x1f1ff && runes[1] >= 0x1f1e6 && runes[1] <= 0x1f1ff {
		runes = runes[2:]
		for len(runes) > 0 && unicode.IsSpace(runes[0]) {
			runes = runes[1:]
		}
	}
	return string([]rune{0x1f1e6 + rune(code[0]-'A'), 0x1f1e6 + rune(code[1]-'A')}) + " " + strings.TrimSpace(string(runes))
}
func (r *Repository) ApplyCountryFlags(id string, targets []FlagTarget, countries map[string]FlagCountry) (Document, error) {
	renamed, skipped := []any{}, []any{}
	unchanged := 0
	err := r.Mutate(id, func(doc Document) error {
		byName := map[string]Document{}
		used := map[string]bool{}
		for _, key := range []string{"proxies", "proxy-groups"} {
			for _, v := range rows(doc, key) {
				n := v.(map[string]any)
				used[stringValue(n["name"])] = true
				if key == "proxies" {
					byName[stringValue(n["name"])] = n
				}
			}
		}
		for _, target := range targets {
			skip := func(reason string) { skipped = append(skipped, Document{"name": target.Name, "reason": reason}) }
			node := byName[target.Name]
			if node == nil || managednodes.Identity(node) != target.Identity {
				skip("节点已变化，请刷新后重试")
				continue
			}
			country := countries[target.Server]
			if country.Error != "" {
				skip(country.Error)
				continue
			}
			code := country.Code
			if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
				skip("国家代码无效")
				continue
			}
			name := countryName(target.Name, code)
			if name == target.Name {
				unchanged++
				continue
			}
			if used[name] {
				skip("添加国家标识后名称重复")
				continue
			}
			node["name"] = name
			if err := ValidateNode(node); err != nil {
				node["name"] = target.Name
				skip("节点名称或配置无效")
				continue
			}
			delete(used, target.Name)
			used[name] = true
			replaceReferences(doc, target.Name, name)
			renamed = append(renamed, Document{"old": target.Name, "new": name, "country": code, "ip": country.IP})
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return Document{"updated": len(renamed), "unchanged": unchanged, "renamed": renamed, "skipped": skipped}, nil
}
