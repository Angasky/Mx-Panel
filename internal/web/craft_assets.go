package web

import (
	"bytes"
	"embed"
	"net/http"
	"strings"
	"time"
)

//go:embed assets/craft/*
var craftAssets embed.FS

func craftAsset(w http.ResponseWriter, r *http.Request) bool {
	const prefix = "/sub/ui-craft/"
	if !strings.HasPrefix(r.URL.Path, prefix) {
		return false
	}
	name := strings.TrimPrefix(r.URL.Path, prefix)
	switch name {
	case "block.svg", "dirt.svg", "stone.svg", "wood.svg", "overworld.png", "Silkscreen-Regular.ttf", "Silkscreen-OFL.txt":
	default:
		problem(w, 404, "资源不存在")
		return true
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	data, e := craftAssets.ReadFile("assets/craft/" + name)
	if e != nil {
		problem(w, 404, "资源不存在")
		return true
	}
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	return true
}
