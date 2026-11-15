package remote

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

type ServerGroup struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}
type ServerGroups struct {
	Groups      []ServerGroup     `json:"groups"`
	Assignments map[string]string `json:"assignments"`
	Revision    string            `json:"revision"`
}
type ServerGroupChange struct {
	Action   string   `json:"action"`
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Servers  []string `json:"servers"`
	Revision string   `json:"revision"`
}

var ErrGroupConflict = errors.New("服务器分组已变化，请刷新后重试")

func groupSnapshot(data map[string]any) (ServerGroups, error) {
	s := ServerGroups{Groups: []ServerGroup{}, Assignments: map[string]string{}}
	if raw, ok := data["serverGroups"]; ok {
		b, e := json.Marshal(raw)
		if e != nil {
			return s, e
		}
		if e = json.Unmarshal(b, &s); e != nil || s.Groups == nil || s.Assignments == nil {
			return s, errors.New("服务器分组数据损坏")
		}
	}
	valid := map[string]bool{}
	for _, v := range data["servers"].([]any) {
		valid[value(v.(map[string]any)["id"])] = true
	}
	for id := range s.Assignments {
		if !valid[id] {
			delete(s.Assignments, id)
		}
	}
	s.Revision = ""
	b, _ := json.Marshal(s)
	h := sha256.Sum256(b)
	s.Revision = hex.EncodeToString(h[:])
	return s, nil
}
func (m *Manager) ServerGroups(change *ServerGroupChange) (ServerGroups, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, e := m.load()
	if e != nil {
		return ServerGroups{}, e
	}
	s, e := groupSnapshot(data)
	if e != nil || change == nil {
		return s, e
	}
	if change.Revision != s.Revision {
		return s, ErrGroupConflict
	}
	index := -1
	for i, g := range s.Groups {
		if g.ID == change.ID {
			index = i
		}
	}
	switch change.Action {
	case "create", "rename":
		name := strings.TrimSpace(change.Name)
		if name == "" || utf8.RuneCountInString(name) > 60 || !utf8.ValidString(name) || strings.ContainsFunc(name, unicode.IsControl) {
			return s, errors.New("分组名称须为 1–60 个字符，不能包含控制字符")
		}
		for _, g := range s.Groups {
			if strings.EqualFold(g.Name, name) && (change.Action == "create" || g.ID != change.ID) {
				return s, errors.New("分组名称已存在")
			}
		}
		if change.Action == "create" {
			if len(s.Groups) >= 100 {
				return s, errors.New("最多创建 100 个分组")
			}
			b := make([]byte, 16)
			if _, e = rand.Read(b); e != nil {
				return s, e
			}
			s.Groups = append(s.Groups, ServerGroup{hex.EncodeToString(b), name})
		} else {
			if index < 0 {
				return s, errors.New("分组不存在")
			}
			s.Groups[index].Name = name
		}
	case "delete":
		if index < 0 {
			return s, errors.New("分组不存在")
		}
		s.Groups = append(s.Groups[:index], s.Groups[index+1:]...)
		for id, g := range s.Assignments {
			if g == change.ID {
				delete(s.Assignments, id)
			}
		}
	case "assign":
		if change.ID != "" && index < 0 {
			return s, errors.New("分组不存在")
		}
		if len(change.Servers) == 0 || len(change.Servers) > 1000 {
			return s, errors.New("请选择 1–1000 台服务器")
		}
		for _, id := range change.Servers {
			if _, e = find(data, id); e != nil {
				return s, e
			}
		}
		for _, id := range change.Servers {
			if change.ID == "" {
				delete(s.Assignments, id)
			} else {
				s.Assignments[id] = change.ID
			}
		}
	default:
		return s, errors.New("不支持的分组操作")
	}
	s.Revision = ""
	data["serverGroups"] = s
	if e = m.flush(data); e != nil {
		return s, e
	}
	return groupSnapshot(data)
}
