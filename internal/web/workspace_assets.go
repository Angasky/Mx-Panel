package web

import (
	"embed"
	"net/http"
	"sync"
)

//go:embed assets/workspace/*
var workspaceAssets embed.FS
var workspaceDelivery sync.Map

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
	cached, ok := workspaceDelivery.Load(name)
	if !ok {
		data, e := workspaceAssets.ReadFile("assets/workspace/" + name)
		if e != nil {
			problem(w, 404, "界面资源不存在")
			return true
		}
		cached, _ = workspaceDelivery.LoadOrStore(name, makeUIRepresentation(data))
	}
	cached.(*uiRepresentation).serve(w, r, name, kind)
	return true
}
