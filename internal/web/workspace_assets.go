package web

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed assets/workspace/*
var workspaceAssets embed.FS

func workspaceAsset(w http.ResponseWriter, r *http.Request) bool {
	var name, kind string
	switch r.URL.Path {
	case "/sub/status-workspace.css":
		name = "status.css"
		kind = "text/css; charset=utf-8"
	case "/sub/status-workspace.js":
		name = "status.js"
		kind = "text/javascript; charset=utf-8"
	case "/sub/workspace.css":
		name = "workspace.css"
		kind = "text/css; charset=utf-8"
	case "/sub/workspace.js":
		name = "workspace.js"
		kind = "text/javascript; charset=utf-8"
	default:
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	data, e := workspaceAssets.ReadFile("assets/workspace/" + name)
	if e != nil {
		problem(w, 404, "界面资源不存在")
		return true
	}
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	return true
}
