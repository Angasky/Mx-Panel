package web

import (
	_ "embed"
	"encoding/json"
	"net/http"
)

//go:embed assets/globe.js
var globeJS []byte

// The asset contains only code and public-domain coastlines, never server data.
func globeAsset(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/sub/status-globe.js" {
		return false
	}
	if r.Method != "GET" && r.Method != "HEAD" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == "GET" {
		_, _ = w.Write(globeJS)
	}
	return true
}

type globePoint struct {
	Label     string  `json:"label"`
	Latitude  float64 `json:"latitude"`
	Longitude float64 `json:"longitude"`
}

func sharedGlobe(servers []sharedMetric) string {
	points := []globePoint{}
	for _, s := range servers {
		if m := s.Metadata; m != nil && m.Public && m.Latitude != nil && m.Longitude != nil {
			points = append(points, globePoint{s.Label, *m.Latitude, *m.Longitude})
		}
	}
	b, _ := json.Marshal(points)
	return string(b)
}
