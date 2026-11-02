package config

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func (r *Repository) Backups(id string) ([]map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, err := r.profile(id)
	if err != nil {
		return nil, err
	}
	directory := filepath.Join(r.Root, "backups")
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return []map[string]any{}, nil
	}
	if err != nil {
		return nil, err
	}
	type row struct {
		info os.FileInfo
		name string
	}
	rows := []row{}
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), p.ID+".") || !strings.HasSuffix(entry.Name(), ".yaml") || entry.Type()&os.ModeSymlink != 0 {
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return nil, err
		}
		if info.Mode().IsRegular() {
			rows = append(rows, row{info: info, name: entry.Name()})
		}
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].info.ModTime().After(rows[j].info.ModTime()) })
	if len(rows) > 100 {
		rows = rows[:100]
	}
	result := []map[string]any{}
	for _, item := range rows {
		result = append(result, map[string]any{"name": item.name, "size": item.info.Size(), "time": item.info.ModTime().Format("2006-01-02 15:04:05")})
	}
	return result, nil
}
func (r *Repository) Restore(id, name string) error {
	r.mu.Lock()
	p, err := r.profile(id)
	r.mu.Unlock()
	if err != nil {
		return err
	}
	if name == "" || strings.ContainsAny(name, "/\\") || !strings.HasPrefix(name, p.ID+".") || !strings.HasSuffix(name, ".yaml") {
		return errors.New("备份不属于当前订阅或名称无效")
	}
	root, err := os.OpenRoot(filepath.Join(r.Root, "backups"))
	if err != nil {
		return errors.New("备份目录读取失败")
	}
	defer root.Close()
	file, err := root.Open(name)
	if err != nil {
		return errors.New("备份不存在或不允许读取")
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 8<<20+1))
	if err != nil || len(data) > 8<<20 {
		return errors.New("备份读取失败或超过大小限制")
	}
	return r.Mutate(id, func(doc Document) error { return ReplaceRaw(doc, map[string]any{"yaml": string(data)}) })
}
