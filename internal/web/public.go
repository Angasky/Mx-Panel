package web

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/subscriptions"
)

func (s *Server) publicRoutes(w http.ResponseWriter, r *http.Request) bool {
	path := r.URL.Path
	if path == "/admin/api/conversions" && r.Method == "GET" {
		source, err := s.repository.ConversionSource(r.Header.Get("X-Profile"), s.now())
		if err != nil {
			problem(w, 400, err.Error())
		} else {
			respond(w, 200, map[string]any{"formats": subscriptions.ConversionReport(source, s.now())})
		}
		return true
	}
	convert := strings.HasPrefix(path, "/convert/")
	raw := strings.HasPrefix(path, "/sub/")
	if !convert && !raw {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Vary", "*")
	if r.Method != "GET" && r.Method != "HEAD" {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, 405, "请求方法不支持")
		return true
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if raw && len(parts) != 2 || convert && len(parts) != 3 {
		problem(w, 404, "订阅不存在")
		return true
	}
	readSubscription := s.repository.PublicSubscription
	if raw {
		readSubscription = s.repository.PublicRawSubscription
	}
	clientIP, _ := s.subscriptionClientIP(r)
	source, err := readSubscription(parts[1], s.now(), clientIP)
	if err != nil {
		if errors.Is(err, config.ErrSubscriptionIPDenied) {
			problem(w, 403, "当前 IP 不在订阅访问白名单中，请联系管理员")
		} else if errors.Is(err, config.ErrSubscriptionBlocked) {
			problem(w, 403, "订阅已过期或流量已用尽")
		} else {
			problem(w, 404, "订阅不存在")
		}
		return true
	}
	body := source.Raw
	extension := ".yaml"
	contentType := "text/yaml; charset=utf-8"
	if convert {
		result, e := subscriptions.Convert(source, parts[2], s.now())
		if e != nil {
			problem(w, 404, "没有可用的客户端导出")
			return true
		}
		body = result.Body
		extension = "-" + parts[2] + ".txt"
		contentType = "text/plain; charset=utf-8"
		if parts[2] == "stash" || parts[2] == "egern" {
			extension = "-" + parts[2] + ".yaml"
			contentType = "text/yaml; charset=utf-8"
		}
		if parts[2] == "quantumult-x" || parts[2] == "surfboard" {
			extension = "-" + parts[2] + ".conf"
		}
		if parts[2] == "loon" {
			extension = "-loon.conf"
		}
		if parts[2] == "surge-routing" {
			extension = "-surge-routing.conf"
		}
		if parts[2] == "surge" {
			extension = "-surge.conf"
		}
		if parts[2] == "shadowrocket-config" {
			extension = "-shadowrocket.conf"
		}
		if parts[2] == "v2rayn-ha" || parts[2] == "v2rayng-ha" || parts[2] == "sing-box" || parts[2] == "sing-box-routing" || parts[2] == "xray" {
			extension = "-" + parts[2] + ".json"
			contentType = "application/json; charset=utf-8"
		}
		w.Header().Set("X-Mxioc-Skipped-Nodes", strconv.Itoa(len(result.Skipped)))
	}
	w.Header().Set("Profile-Update-Interval", "6")
	w.Header().Set("Profile-Title", "base64:"+base64.StdEncoding.EncodeToString([]byte(source.Name)))
	if source.Userinfo != "" {
		w.Header().Set("Subscription-Userinfo", source.Userinfo)
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", "attachment; filename*=UTF-8''"+url.PathEscape(source.Name+extension))
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != "HEAD" {
		_, _ = w.Write(body)
	}
	return true
}
