package web

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/subsource"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type externalSnapshot struct {
	Time int64 `json:"time"`
	subsource.Traffic
}
type externalSource struct {
	ID      string             `json:"id"`
	Name    string             `json:"name"`
	Secret  string             `json:"secret,omitempty"`
	Checked int64              `json:"checked"`
	Error   string             `json:"error,omitempty"`
	Samples []externalSnapshot `json:"samples"`
}

func (s *Server) readExternal() ([]externalSource, error) {
	rows := []externalSource{}
	b, e := os.ReadFile(filepath.Join(s.options.Root, "external-traffic.json"))
	if os.IsNotExist(e) {
		return rows, nil
	}
	if e != nil {
		return nil, e
	}
	if len(b) > 2<<20 {
		return nil, errors.New("外部流量记录过大")
	}
	e = json.Unmarshal(b, &rows)
	if len(rows) > 50 {
		return nil, errors.New("订阅数量超出限制")
	}
	return rows, e
}
func (s *Server) saveExternal(rows []externalSource) error {
	b, e := json.Marshal(rows)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".external-traffic-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "external-traffic.json"))
}
func trimExternal(rows []externalSource, now time.Time) {
	cutoff := now.UTC().AddDate(0, 0, -29).Format("2006-01-02")
	for i := range rows {
		samples := []externalSnapshot{}
		for _, p := range rows[i].Samples {
			if time.Unix(p.Time, 0).UTC().Format("2006-01-02") >= cutoff && p.Time <= now.Unix() {
				samples = append(samples, p)
			}
		}
		if len(samples) > 30 {
			samples = samples[len(samples)-30:]
		}
		rows[i].Samples = samples
	}
}
func (s *Server) externalTrafficRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/external-traffic" {
		return false
	}
	if r.Method != "GET" && r.Method != "POST" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.externalMu.Lock()
	defer s.externalMu.Unlock()
	rows, e := s.readExternal()
	if e != nil {
		problem(w, 500, "外部流量记录读取失败")
		return true
	}
	now := s.now()
	trimExternal(rows, now)
	if r.Method == "POST" {
		var in struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			URL  string `json:"url"`
		}
		if readJSON(w, r, &in) != nil {
			problem(w, 400, "请求格式无效")
			return true
		}
		idx := -1
		for i := range rows {
			if rows[i].ID == in.ID {
				idx = i
				break
			}
		}
		if in.ID != "" && idx < 0 {
			problem(w, 404, "外部订阅不存在")
			return true
		}
		manager, err := s.remoteManager()
		if err != nil {
			problem(w, 500, "凭据存储不可用")
			return true
		}
		if idx < 0 {
			in.Name = strings.TrimSpace(in.Name)
			in.URL = strings.TrimSpace(in.URL)
			u, err := url.Parse(in.URL)
			if len(rows) >= 50 || !utf8.ValidString(in.Name) || len([]rune(in.Name)) < 1 || len([]rune(in.Name)) > 60 || strings.ContainsFunc(in.Name, unicode.IsControl) || len(in.URL) > 8192 || err != nil || u == nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil {
				problem(w, 400, "最多 50 个订阅；名称 1–60 字，地址须为不含认证段的 HTTPS 链接")
				return true
			}
			sealed, err := manager.SealUser(map[string]any{"url": in.URL})
			if err != nil {
				problem(w, 500, "地址加密失败")
				return true
			}
			rows = append(rows, externalSource{ID: rand.Text(), Name: in.Name, Secret: sealed, Samples: []externalSnapshot{}})
			idx = len(rows) - 1
		} else {
			if now.Unix()-rows[idx].Checked < 60 {
				problem(w, 429, "每个外部订阅请间隔至少 60 秒刷新")
				return true
			}
			secret, err := manager.OpenUser(rows[idx].Secret)
			if err != nil {
				problem(w, 500, "地址解密失败")
				return true
			}
			in.URL, _ = secret["url"].(string)
		}
		ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
		defer cancel()
		fetch := s.fetchExternalTraffic
		if fetch == nil {
			fetch = subsource.NewClient().FetchTraffic
		}
		info, err := fetch(ctx, in.URL)
		rows[idx].Checked = now.Unix()
		rows[idx].Error = ""
		if err != nil {
			rows[idx].Error = "未获取有效流量信息：上游未提供标准响应头，或请求失败。旧快照不代表当前剩余额度。"
		} else {
			sample := externalSnapshot{Time: now.Unix(), Traffic: info}
			samples := rows[idx].Samples
			if len(samples) > 0 && time.Unix(samples[len(samples)-1].Time, 0).UTC().Format("2006-01-02") == now.UTC().Format("2006-01-02") {
				samples[len(samples)-1] = sample
			} else {
				samples = append(samples, sample)
			}
			rows[idx].Samples = samples
		}
	} else if r.Method == "DELETE" {
		id := r.URL.Query().Get("id")
		found := false
		next := []externalSource{}
		for _, row := range rows {
			if row.ID == id {
				found = true
			} else {
				next = append(next, row)
			}
		}
		if !found {
			problem(w, 404, "外部订阅不存在")
			return true
		}
		rows = next
	}
	if e = s.saveExternal(rows); e != nil {
		problem(w, 500, "外部流量记录保存失败")
		return true
	}
	for i := range rows {
		rows[i].Secret = ""
	}
	respond(w, 200, map[string]any{"sources": rows, "timezone": "UTC"})
	return true
}
