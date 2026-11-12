package web

import (
	"bytes"
	"embed"
	"net/http"
	"time"
)

//go:embed assets/fonts/*
var uiFonts embed.FS

func uiFontAsset(w http.ResponseWriter, r *http.Request) bool {
	var name string
	switch r.URL.Path {
	case "/sub/ui-fonts/inter.woff2":
		name = "inter.woff2"
	case "/sub/ui-fonts/noto-ui.woff2":
		name = "noto-ui.woff2"
	default:
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	data, e := uiFonts.ReadFile("assets/fonts/" + name)
	if e != nil {
		problem(w, 404, "字体不存在")
		return true
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	return true
}
