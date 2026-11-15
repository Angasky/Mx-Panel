package web

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Only public UI files use this cache; authenticated API responses never do.
type uiRepresentation struct {
	plain, zipped []byte
	etag          string
}

func makeUIRepresentation(data []byte) *uiRepresentation {
	var b bytes.Buffer
	z, _ := gzip.NewWriterLevel(&b, gzip.BestCompression)
	_, _ = z.Write(data)
	_ = z.Close()
	return &uiRepresentation{data, b.Bytes(), fmt.Sprintf(`"%x"`, sha256.Sum256(data))}
}
func acceptsUIGzip(value string) bool {
	explicit, wild := -1.0, 0.0
	for _, part := range strings.Split(value, ",") {
		fields := strings.Split(part, ";")
		name := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		for _, param := range fields[1:] {
			k, v, ok := strings.Cut(strings.TrimSpace(param), "=")
			if ok && strings.EqualFold(k, "q") {
				n, e := strconv.ParseFloat(v, 64)
				if e != nil || n < 0 || n > 1 {
					q = 0
				} else {
					q = n
				}
			}
		}
		if name == "gzip" {
			explicit = q
		}
		if name == "*" {
			wild = q
		}
	}
	if explicit >= 0 {
		return explicit > 0
	}
	return wild > 0
}
func (a *uiRepresentation) serve(w http.ResponseWriter, r *http.Request, name, kind string) {
	w.Header().Set("Content-Type", kind)
	w.Header().Set("Cache-Control", "public, no-cache")
	w.Header().Add("Vary", "Accept-Encoding")
	data, tag := a.plain, a.etag
	if acceptsUIGzip(r.Header.Get("Accept-Encoding")) && len(a.zipped) < len(data) {
		data = a.zipped
		tag = strings.TrimSuffix(tag, `"`) + `-gzip"`
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("ETag", tag)
	http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
}

var uiHTMLCache struct {
	sync.Mutex
	path  string
	info  os.FileInfo
	asset *uiRepresentation
}

func serveUIHTML(w http.ResponseWriter, r *http.Request, path string) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		http.NotFound(w, r)
		return
	}
	uiHTMLCache.Lock()
	if uiHTMLCache.path != path || uiHTMLCache.info == nil || !os.SameFile(info, uiHTMLCache.info) || info.Size() != uiHTMLCache.info.Size() || !info.ModTime().Equal(uiHTMLCache.info.ModTime()) {
		data, e := os.ReadFile(path)
		if e != nil {
			uiHTMLCache.Unlock()
			http.NotFound(w, r)
			return
		}
		uiHTMLCache.path = path
		uiHTMLCache.info = info
		uiHTMLCache.asset = makeUIRepresentation(data)
	}
	asset := uiHTMLCache.asset
	uiHTMLCache.Unlock()
	asset.serve(w, r, "index.html", "text/html; charset=utf-8")
}
