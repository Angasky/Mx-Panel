package web

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	qrcode "github.com/skip2/go-qrcode"
)

func (s *Server) nodeLink(r *http.Request) (map[string]any, error) {
	name := r.URL.Query().Get("name")
	if name == "" {
		return nil, errors.New("节点名称不能为空")
	}
	profile := r.Header.Get("X-Profile")
	if profile == "" {
		profile = r.URL.Query().Get("profile")
	}
	snapshot, err := s.repository.Snapshot(profile)
	if err != nil {
		return nil, err
	}
	for _, value := range snapshot["nodes"].([]any) {
		row := value.(map[string]any)
		if row["name"] == name {
			node := row["config"].(map[string]any)
			uri, err := links.Export(node)
			if err != nil {
				return nil, err
			}
			return map[string]any{"name": node["name"], "type": node["type"], "uri": uri}, nil
		}
	}
	return nil, errors.New("节点不存在")
}
func drawQR(w http.ResponseWriter, value string) {
	if value == "" || len(value) > 8192 {
		problem(w, 400, "二维码内容为空或过长")
		return
	}
	qr, err := qrcode.New(value, qrcode.Medium)
	if err != nil {
		problem(w, 400, "二维码内容超过编码范围")
		return
	}
	matrix := qr.Bitmap()
	var path strings.Builder
	for y, row := range matrix {
		for x, on := range row {
			if on {
				fmt.Fprintf(&path, "M%d %dh1v1h-1z", x, y)
			}
		}
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fmt.Fprintf(w, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="320" height="320" shape-rendering="crispEdges"><rect width="100%%" height="100%%" fill="#fff"/><path d="%s" fill="#000"/></svg>`, len(matrix), len(matrix), path.String())
}
func (s *Server) importNodes(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Links       string
		AddToGroups bool
	}
	if err := readJSON(w, r, &input); err != nil {
		problem(w, 400, err.Error())
		return
	}
	if len(input.Links) > 2<<20 {
		problem(w, 400, "导入内容超过限制")
		return
	}
	failed := []any{}
	renamed := []any{}
	nodes := []map[string]any{}
	total := 0
	for line, value := range strings.Split(input.Links, "\n") {
		if strings.TrimSpace(value) == "" {
			continue
		}
		total++
		parsed, err := links.ParseMany(value)
		if err == nil {
			for _, node := range parsed {
				if e := config.ValidateNode(node); e != nil {
					err = e
					break
				}
			}
		}
		if err != nil {
			failed = append(failed, map[string]any{"line": line + 1, "reason": "节点链接无效，或含暂未适配参数"})
			continue
		}
		if len(nodes)+len(parsed) > 20000 {
			problem(w, 400, "导入节点数量超过 20000")
			return
		}
		nodes = append(nodes, parsed...)
	}
	if total == 0 {
		problem(w, 400, "没有节点链接")
		return
	}
	if len(nodes) == 0 {
		respond(w, 200, map[string]any{"total": total, "added": 0, "failed": failed, "renamed": renamed})
		return
	}
	err := s.repository.Mutate(r.Header.Get("X-Profile"), func(doc config.Document) error {
		names := map[string]bool{}
		for _, key := range []string{"proxies", "proxy-groups"} {
			if list, ok := doc[key].([]any); ok {
				for _, value := range list {
					row := value.(map[string]any)
					names[fmt.Sprint(row["name"])] = true
				}
			}
		}
		for _, node := range nodes {
			original := fmt.Sprint(node["name"])
			name := original
			for i := 2; names[name]; i++ {
				name = original + " (" + strconv.Itoa(i) + ")"
			}
			if name != original {
				renamed = append(renamed, map[string]any{"from": original, "to": name})
				node["name"] = name
			}
			names[name] = true
			if err := config.EditNode(doc, "POST", map[string]any{"config": node, "addToGroups": input.AddToGroups}); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		problem(w, 400, err.Error())
		return
	}
	respond(w, 200, map[string]any{"total": total, "added": len(nodes), "failed": failed, "renamed": renamed})
}

func (s *Server) linkRoutes(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == "POST" && r.URL.Path == "/admin/api/import-node" {
		s.importNodes(w, r)
		return true
	}
	if r.Method != "GET" {
		return false
	}
	switch r.URL.Path {
	case "/admin/api/nodes/share", "/admin/api/nodes/qrcode":
		value, err := s.nodeLink(r)
		if err != nil {
			problem(w, 400, err.Error())
			return true
		}
		if r.URL.Path == "/admin/api/nodes/share" {
			respond(w, 200, value)
		} else {
			drawQR(w, value["uri"].(string))
		}
		return true
	case "/admin/api/qrcode":
		drawQR(w, r.URL.Query().Get("url"))
		return true
	}
	return false
}
