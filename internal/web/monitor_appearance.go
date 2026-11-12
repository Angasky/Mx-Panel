package web

import (
	"bytes"
	"encoding/base64"
	"html/template"
	"image"
	_ "image/jpeg"
	_ "image/png"
	"strings"
	"unicode"
	"unicode/utf8"
)

type monitorAppearance struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Logo        string `json:"logo"`
	Theme       string `json:"theme"`
	HideGlobe   bool   `json:"hideGlobe"`
}

func validMonitorAppearance(a monitorAppearance) bool {
	for _, v := range []struct {
		s string
		n int
	}{{a.Title, 60}, {a.Description, 200}} {
		if !utf8.ValidString(v.s) || utf8.RuneCountInString(v.s) > v.n || strings.ContainsFunc(v.s, unicode.IsControl) {
			return false
		}
	}
	switch a.Theme {
	case "", "amber", "slate", "dark", "craft":
	default:
		return false
	}
	if a.Logo == "" {
		return true
	}
	if len(a.Logo) > 33000 {
		return false
	}
	format := ""
	for _, f := range []string{"png", "jpeg"} {
		if strings.HasPrefix(a.Logo, "data:image/"+f+";base64,") {
			format = f
			break
		}
	}
	if format == "" {
		return false
	}
	raw, e := base64.StdEncoding.Strict().DecodeString(strings.SplitN(a.Logo, ",", 2)[1])
	if e != nil || len(raw) > 24*1024 {
		return false
	}
	cfg, actual, e := image.DecodeConfig(bytes.NewReader(raw))
	if e != nil || actual != format || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 512 || cfg.Height > 512 {
		return false
	}
	_, _, e = image.Decode(bytes.NewReader(raw))
	return e == nil
}
func monitorAppearanceDefaults(a monitorAppearance) monitorAppearance {
	if strings.TrimSpace(a.Title) == "" {
		a.Title = "MXIOC · 服务器状态"
	}
	if strings.TrimSpace(a.Description) == "" {
		a.Description = "管理员选择分享的资源指标 · 每 60 秒刷新"
	}
	if a.Theme == "" {
		a.Theme = "amber"
	}
	return a
}

// Only validated local raster data is trusted; external URLs and SVG are rejected.
func monitorLogoURL(logo string) template.URL {
	if logo != "" && validMonitorAppearance(monitorAppearance{Logo: logo}) {
		return template.URL(logo)
	}
	return ""
}
