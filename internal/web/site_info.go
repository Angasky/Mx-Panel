package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

type siteInfo struct {
	ThemeNames         map[string]string `json:"themeNames,omitempty"`
	SubscriptionOrigin string            `json:"subscriptionOrigin,omitempty"`
	Logo               string            `json:"logo,omitempty"`
	Name               string            `json:"name"`
	Description        string            `json:"description"`
	Announcement       string            `json:"announcement"`
}

func validSiteInfo(c siteInfo) bool {
	for key, name := range c.ThemeNames {
		switch key {
		case "craft", "slate", "high", "low", "pink", "amber":
		default:
			return false
		}
		if !utf8.ValidString(name) || utf8.RuneCountInString(name) > 24 || strings.ContainsFunc(name, unicode.IsControl) {
			return false
		}
	}
	if normalized, err := normalizeSubscriptionOrigin(c.SubscriptionOrigin); err != nil || normalized != c.SubscriptionOrigin {
		return false
	}
	for _, field := range []struct {
		text      string
		limit     int
		multiline bool
	}{
		{c.Name, 60, false}, {c.Description, 160, false}, {c.Announcement, 1000, true},
	} {
		if !utf8.ValidString(field.text) || utf8.RuneCountInString(field.text) > field.limit || strings.ContainsFunc(field.text, func(r rune) bool {
			return unicode.IsControl(r) && !(field.multiline && (r == '\n' || r == '\t'))
		}) {
			return false
		}
	}
	return validMonitorAppearance(monitorAppearance{Logo: c.Logo})
}

func siteInfoRevision(c siteInfo) string {
	b, _ := json.Marshal(c)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (s *Server) readSiteInfo() (siteInfo, error) {
	var c siteInfo
	b, e := os.ReadFile(filepath.Join(s.options.Root, "site-info.json"))
	if os.IsNotExist(e) {
		return c, nil
	}
	if e != nil {
		return c, e
	}
	if len(b) > 48<<10 || strings.TrimSpace(string(b)) == "null" || json.Unmarshal(b, &c) != nil || !validSiteInfo(c) {
		return siteInfo{}, errors.New("网站信息配置无效")
	}
	return c, nil
}

func (s *Server) writeSiteInfo(c siteInfo) error {
	b, e := json.Marshal(c)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".site-info-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "site-info.json"))
}

// Every field is explicitly public. Never extend this response with account or
// server settings; login branding must work without a session.
func (s *Server) siteInfoPublic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		problem(w, 405, "请求方法不支持")
		return
	}
	s.siteInfoMu.Lock()
	defer s.siteInfoMu.Unlock()
	c, e := s.readSiteInfo()
	if e != nil {
		problem(w, 503, "网站信息暂不可用")
		return
	}
	respond(w, 200, c)
}

func (s *Server) siteInfoAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/site-info" {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" && r.Method != "PUT" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.siteInfoMu.Lock()
	defer s.siteInfoMu.Unlock()
	c, e := s.readSiteInfo()
	if e != nil {
		problem(w, 500, "网站信息读取失败")
		return true
	}
	if r.Method == "PUT" {
		var input struct {
			Config *struct {
				ThemeNames         *map[string]string `json:"themeNames"`
				Name               string             `json:"name"`
				Description        string             `json:"description"`
				Announcement       string             `json:"announcement"`
				Logo               *string            `json:"logo"`
				SubscriptionOrigin *string            `json:"subscriptionOrigin"`
			} `json:"config"`
			Revision string `json:"revision"`
		}
		if err := readJSON(w, r, &input); err != nil {
			problem(w, 400, err.Error())
			return true
		}
		if input.Config == nil {
			problem(w, 400, "请提供网站信息")
			return true
		}
		next := siteInfo{Name: input.Config.Name, Description: input.Config.Description, Announcement: input.Config.Announcement, Logo: c.Logo, SubscriptionOrigin: c.SubscriptionOrigin}
		next.ThemeNames = c.ThemeNames
		if input.Config.ThemeNames != nil {
			next.ThemeNames = *input.Config.ThemeNames
		}
		if input.Config.Logo != nil {
			next.Logo = *input.Config.Logo
		}
		if input.Config.SubscriptionOrigin != nil {
			origin, err := normalizeSubscriptionOrigin(*input.Config.SubscriptionOrigin)
			if err != nil {
				problem(w, 400, err.Error())
				return true
			}
			next.SubscriptionOrigin = origin
		}
		if !validSiteInfo(next) {
			problem(w, 400, "网站信息无效：主题名称仅支持六套内置主题，每项最多 24 字且不能换行；名称最多 60 字、简介最多 160 字、公告最多 1000 字；Logo 仅支持规定尺寸的 PNG/JPEG")
			return true
		}
		if input.Revision != siteInfoRevision(c) {
			problem(w, 409, "网站信息已变更，请重新打开设置后再保存")
			return true
		}
		c = next
		if c.ThemeNames != nil {
			names := map[string]string{}
			for key, name := range c.ThemeNames {
				if name = strings.TrimSpace(name); name != "" {
					names[key] = name
				}
			}
			c.ThemeNames = names
		}
		c.Name = strings.TrimSpace(c.Name)
		c.Description = strings.TrimSpace(c.Description)
		c.Announcement = strings.TrimSpace(c.Announcement)
		if e = s.writeSiteInfo(c); e != nil {
			problem(w, 500, "网站信息保存失败")
			return true
		}
	}
	respond(w, 200, map[string]any{"config": c, "revision": siteInfoRevision(c)})
	return true
}
