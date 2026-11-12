package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/Angasky/dingzhi-ban/internal/monitorhistory"
	"github.com/Angasky/dingzhi-ban/internal/netprobe"
	"golang.org/x/net/websocket"
	"html/template"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

type sharedMonitor struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}
type monitorShare struct {
	Appearance monitorAppearance `json:"appearance"`
	Public     bool              `json:"public"`
	Enabled    bool              `json:"enabled"`
	Digest     string            `json:"digest"`
	Servers    []sharedMonitor   `json:"servers"`
	Updated    int64             `json:"updated"`
}
type sharedMetric struct {
	ICMPProbes []netprobe.Result      `json:"icmpProbes,omitempty"`
	Metadata   *serverMetadata        `json:"metadata,omitempty"`
	Probes     []netprobe.Result      `json:"tcpProbes,omitempty"`
	History    []monitorhistory.Point `json:"-"`
	Index      int                    `json:"index"`
	Label      string                 `json:"label"`
	Status     string                 `json:"status"`
	SampledAt  int64                  `json:"sampledAt"`
	CPU        *float64               `json:"cpu"`
	Memory     *float64               `json:"memory"`
	RXRate     *float64               `json:"rxRate"`
	TXRate     *float64               `json:"txRate"`
}
type sharedReport struct {
	Appearance  monitorAppearance `json:"appearance"`
	GeneratedAt int64             `json:"generatedAt"`
	Servers     []sharedMetric    `json:"servers"`
}

func (s *Server) sharePath() string { return filepath.Join(s.options.Root, "monitor-sharing.json") }
func validSharedServers(servers []sharedMonitor) bool {
	if len(servers) > 32 {
		return false
	}
	seen := map[string]bool{}
	for _, v := range servers {
		if v.ID == "" || seen[v.ID] || !utf8.ValidString(v.Label) || utf8.RuneCountInString(strings.TrimSpace(v.Label)) < 1 || utf8.RuneCountInString(v.Label) > 60 || strings.ContainsFunc(v.Label, unicode.IsControl) {
			return false
		}
		seen[v.ID] = true
	}
	return true
}

// All configuration reads and mutations use shareMu. Tokens are never persisted.
func (s *Server) readShare() (monitorShare, error) {
	c := monitorShare{Servers: []sharedMonitor{}}
	data, err := os.ReadFile(s.sharePath())
	if os.IsNotExist(err) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if len(data) > 64<<10 || json.Unmarshal(data, &c) != nil || !validSharedServers(c.Servers) || !validMonitorAppearance(c.Appearance) {
		return c, errors.New("监控分享配置损坏")
	}
	if c.Digest != "" {
		d, e := hex.DecodeString(c.Digest)
		if e != nil || len(d) != 32 {
			return c, errors.New("监控分享凭据损坏")
		}
	}
	if c.Enabled && ((!c.Public && c.Digest == "") || len(c.Servers) == 0) {
		return c, errors.New("监控分享配置不完整")
	}
	return c, nil
}
func (s *Server) writeShare(c monitorShare) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.options.Root, ".monitor-share-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err = f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), s.sharePath())
}
func (s *Server) monitorShareAdmin(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/admin/api/servers/sharing" {
		return false
	}
	if r.Method != "GET" && r.Method != "PUT" && r.Method != "POST" && r.Method != "DELETE" {
		problem(w, 405, "请求方法不支持")
		return true
	}
	s.shareMu.Lock()
	defer s.shareMu.Unlock()
	c, err := s.readShare()
	if err != nil && r.Method != "DELETE" {
		problem(w, 500, "监控分享配置读取失败")
		return true
	}
	if err != nil {
		c = monitorShare{Servers: []sharedMonitor{}}
	}
	token := ""
	if r.Method == "PUT" || r.Method == "POST" {
		var input struct {
			Appearance *monitorAppearance `json:"appearance"`
			Public     bool               `json:"public"`
			Enabled    bool               `json:"enabled"`
			Servers    []sharedMonitor    `json:"servers"`
		}
		if readJSON(w, r, &input) != nil || !validSharedServers(input.Servers) {
			problem(w, 400, "最多分享 32 台服务器，公开名称需为 1–60 个字符且不能包含控制字符")
			return true
		}
		if input.Appearance != nil {
			if !validMonitorAppearance(*input.Appearance) {
				problem(w, 400, "标题最多 60 字、介绍最多 200 字；Logo 仅支持 24 KiB 内且尺寸不超过 512×512 的 PNG/JPEG")
				return true
			}
			c.Appearance = *input.Appearance
		}
		manager, e := s.remoteManager()
		if e != nil {
			problem(w, 500, "服务器数据读取失败")
			return true
		}
		for _, server := range input.Servers {
			if _, e = manager.Record(server.ID); e != nil {
				problem(w, 400, "选择的服务器不存在，请刷新列表")
				return true
			}
		}
		c.Servers = input.Servers
		c.Enabled = input.Enabled
		c.Public = input.Public
		if r.Method == "POST" {
			if len(c.Servers) == 0 {
				problem(w, 400, "请先选择至少一台服务器")
				return true
			}
			raw := make([]byte, 32)
			if _, e = rand.Read(raw); e != nil {
				problem(w, 500, "访问凭据创建失败")
				return true
			}
			token = base64.RawURLEncoding.EncodeToString(raw)
			digest := sha256.Sum256([]byte(token))
			c.Digest = hex.EncodeToString(digest[:])
			c.Enabled = true
		}
		if c.Enabled && (len(c.Servers) == 0 || !c.Public && c.Digest == "") {
			problem(w, 400, "请先选择服务器并生成访问链接")
			return true
		}
	} else if r.Method == "DELETE" {
		c.Enabled = false
		c.Public = false
		c.Digest = ""
	}
	if r.Method != "GET" {
		c.Updated = s.now().Unix()
		if err = s.writeShare(c); err != nil {
			problem(w, 500, "监控分享保存失败")
			return true
		}
	}
	result := map[string]any{"appearance": c.Appearance, "public": c.Public, "publicURL": "/sub/status-public", "enabled": c.Enabled, "servers": c.Servers, "hasLink": c.Digest != "", "updated": c.Updated}
	if token != "" {
		result["url"] = "/sub/status/" + token
		result["token"] = token
		result["api"] = "/sub/status-api"
	}
	respond(w, 200, result)
	return true
}
func (s *Server) sharedMetrics(c monitorShare) sharedReport {
	report := sharedReport{Appearance: monitorAppearanceDefaults(c.Appearance), GeneratedAt: s.now().Unix(), Servers: []sharedMetric{}}
	manager, err := s.remoteManager()
	if err != nil {
		return report
	}
	for index, item := range c.Servers {
		if _, e := manager.Record(item.ID); e != nil {
			continue
		}
		metric := sharedMetric{Index: index, Label: item.Label, Status: "unavailable"}
		s.metadataMu.Lock()
		metadata, metadataErr := s.readMetadata(item.ID)
		s.metadataMu.Unlock()
		if metadataErr == nil && metadata.Public {
			metric.Metadata = &metadata
		}
		s.agentMu.Lock()
		for _, p := range s.agentViews[item.ID].Probes {
			if p.Time >= s.now().Unix()-120 {
				if p.Method == "icmp" {
					metric.ICMPProbes = append(metric.ICMPProbes, p)
				} else {
					metric.Probes = append(metric.Probes, p)
				}
			}
		}
		s.agentMu.Unlock()
		state, e := s.history.Read(item.ID, s.now())
		if e == nil {
			switch {
			case !state.Enabled:
				metric.Status = "paused"
			case len(state.Points) == 0:
				metric.Status = "pending"
			default:
				p := state.Points[len(state.Points)-1]
				metric.SampledAt = p.Time
				if report.GeneratedAt-p.Time > 120 {
					metric.Status = "stale"
				} else if !p.OK {
					metric.Status = "failed"
				} else {
					metric.Status = "fresh"
					metric.CPU = p.CPU
					metric.Memory = p.Memory
					metric.RXRate = p.RXRate
					metric.TXRate = p.TXRate
				}
			}
		}
		report.Servers = append(report.Servers, metric)
	}
	return report
}
func (s *Server) monitorSharePublic(w http.ResponseWriter, r *http.Request) bool {
	stream := r.URL.Path == "/sub/status-ws"
	public := r.URL.Path == "/sub/status-public"
	series := r.URL.Path == "/sub/status-series"
	api := r.URL.Path == "/sub/status-api" || series || stream
	page := strings.HasPrefix(r.URL.Path, "/sub/status/")
	if !api && !page && !public {
		return false
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	if r.Method != "GET" {
		w.Header().Set("Allow", "GET, HEAD")
		problem(w, 405, "请求方法不支持")
		return true
	}
	if !s.secure(r) {
		problem(w, 426, "监控分享必须通过 HTTPS 访问")
		return true
	}
	token := strings.TrimPrefix(r.URL.Path, "/sub/status/")
	if api {
		auth := r.Header.Get("Authorization")
		if auth != "" && !strings.HasPrefix(auth, "Bearer ") {
			problem(w, 404, "分享不存在或已停用")
			return true
		}
		token = strings.TrimPrefix(auth, "Bearer ")
	}
	if public {
		token = ""
	}
	if token != "" {
		decoded, e := base64.RawURLEncoding.DecodeString(token)
		if len(token) != 43 || e != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != token {
			problem(w, 404, "分享不存在或已停用")
			return true
		}
	}
	slots := s.shareSlots
	if stream {
		slots = s.shareStreamSlots
	}
	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		w.Header().Set("Retry-After", "5")
		problem(w, 429, "请求繁忙，请稍后重试")
		return true
	}
	s.shareMu.Lock()
	c, err := s.readShare()
	digest := sha256.Sum256([]byte(token))
	expected, e := hex.DecodeString(c.Digest)
	if err != nil || !c.Enabled || !(c.Public && (public || api && token == "") || token != "" && e == nil && subtle.ConstantTimeCompare(digest[:], expected) == 1) {
		s.shareMu.Unlock()
		problem(w, 404, "分享不存在或已停用")
		return true
	}
	if stream {
		s.shareMu.Unlock()
		if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
			problem(w, 400, "需要 WebSocket 连接")
			return true
		}
		websocket.Server{Handshake: func(*websocket.Config, *http.Request) error { return nil }, Handler: func(ws *websocket.Conn) {
			defer ws.Close()
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			// Read only to detect disconnect; clients cannot issue commands.
			go func() {
				defer cancel()
				ws.MaxPayloadBytes = 1024
				var value string
				for websocket.Message.Receive(ws, &value) == nil {
				}
			}()
			ticker := time.NewTicker(5 * time.Second)
			defer ticker.Stop()
			for {
				s.shareMu.Lock()
				current, readErr := s.readShare()
				expected, decodeErr := hex.DecodeString(current.Digest)
				allowed := readErr == nil && current.Enabled && (current.Public && token == "" || token != "" && decodeErr == nil && subtle.ConstantTimeCompare(digest[:], expected) == 1)
				var report sharedReport
				if allowed {
					report = s.sharedMetrics(current)
				}
				s.shareMu.Unlock()
				if !allowed {
					return
				}
				ws.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if websocket.JSON.Send(ws, report) != nil {
					return
				}
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}}.ServeHTTP(w, r)
		return true
	}
	if series {
		s.sharedSeries(w, r, c)
		s.shareMu.Unlock()
		return true
	}
	report := s.sharedMetrics(c)
	if !api {
		for i := range report.Servers {
			state, e := s.history.Read(c.Servers[report.Servers[i].Index].ID, s.now())
			if e == nil {
				report.Servers[i].History = state.Points
			}
		}
	}
	s.shareMu.Unlock()
	if api {
		respond(w, 200, report)
		return true
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
	if err = monitorShareTemplate.Execute(w, report); err != nil {
		return true
	}
	return true
}

var monitorShareTemplate = template.Must(template.New("monitor-sharing").Funcs(template.FuncMap{
	"logo":  monitorLogoURL,
	"globe": sharedGlobe,
	"latency": func(p *float64) string {
		if p == nil {
			return "失败"
		}
		return fmt.Sprintf("%.1f ms", *p)
	},
	"price": func(v *float64) string {
		if v == nil {
			return "未填写"
		}
		return fmt.Sprintf("%.2f", *v)
	},
	"cycle": func(v string) string {
		return map[string]string{"month": "月", "quarter": "季度", "half-year": "半年", "year": "年", "one-time": "一次性"}[v]
	},
	"expiry": func(v string) string {
		if v == "" {
			return "未填写"
		}
		t, e := time.Parse("2006-01-02", v)
		if e != nil {
			return "无效"
		}
		today := time.Now().UTC().Truncate(24 * time.Hour)
		days := int(t.Sub(today).Hours() / 24)
		if days < 0 {
			return v + " · 已到期"
		}
		return fmt.Sprintf("%s · %d 天后到期（UTC）", v, days)
	},
	"probeError": func(code string) string {
		return map[string]string{"socket-unavailable": "无法创建套接字，请检查权限", "local-error": "本机错误", "send-failed": "发送失败", "cancelled": "探测取消", "timeout": "未收到回包", "dns-failed": "DNS 解析失败", "blocked-address": "地址被拒绝", "connect-failed": "连接失败"}[code]
	},
	"chart": historyChart,
	"status": func(s string) string {
		return map[string]string{"fresh": "采样正常", "paused": "采样已暂停", "pending": "等待首次采样", "stale": "数据已过期", "failed": "采样失败", "unavailable": "暂不可用"}[s]
	},
	"percent": func(p *float64) string {
		if p == nil {
			return "—"
		}
		return fmtPercent(*p)
	},
	"rate": func(p *float64) string {
		if p == nil {
			return "—"
		}
		return fmtRate(*p)
	},
	"stamp": func(t int64) string {
		if t == 0 {
			return "暂无记录"
		}
		return time.Unix(t, 0).UTC().Format("2006-01-02 15:04:05 UTC")
	},
}).Parse(`<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex,nofollow"><meta http-equiv="refresh" content="60"><title>{{.Appearance.Title}}</title><style>
*{box-sizing:border-box}body{margin:0;background:#f7f3ed;color:#302b26;font:16px/1.6 system-ui,-apple-system,"Segoe UI","Noto Sans CJK SC","Microsoft YaHei",sans-serif}main{max-width:1120px;margin:auto;padding:32px 20px}header{border-bottom:1px solid #d7c9bb;margin-bottom:24px}h1{font-size:28px;margin:0}header p,.hint{color:#77685a;font-size:14px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,290px),1fr));gap:20px}article{background:#fffdf8;border:1px solid #d7c9bb;border-radius:16px;box-shadow:3px 4px 0 #e6ded4;padding:22px;min-width:0}h2{font-size:20px;overflow-wrap:anywhere;margin:0 0 10px}.status{display:inline-block;padding:2px 9px;border:1px solid #dcc9b9;border-radius:20px;background:#f5ede4;font-size:13px}.fresh{color:#196b40;background:#edf8ef;border-color:#b8dbc1}dl{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin:20px 0}dt{font-size:13px;color:#77685a}dd{margin:0;font-size:24px;font-weight:650;overflow-wrap:anywhere}footer{margin-top:28px;font-size:13px;color:#77685a}.time{font-size:12px;color:#77685a;overflow-wrap:anywhere}@media(prefers-reduced-motion:reduce){*{scroll-behavior:auto}}
header h1,header p{overflow-wrap:anywhere}.site-brand{display:flex;align-items:center;gap:16px;min-width:0}.site-logo{width:64px;height:64px;object-fit:contain;flex:none;border-radius:12px}header{padding-bottom:18px}.theme-slate{background:#f4f7fb;color:#1e293b}.theme-slate article{background:#fff;border-color:#cbd5e1;box-shadow:0 3px 10px #1e293b0a}.theme-slate header p,.theme-slate .hint,.theme-slate dt,.theme-slate footer,.theme-slate .time{color:#475569}.theme-dark{background:#111827;color:#f1f5f9}.theme-dark article{background:#1e293b;border-color:#475569;box-shadow:none}.theme-dark header p,.theme-dark .hint,.theme-dark dt,.theme-dark footer,.theme-dark .time{color:#cbd5e1}.theme-dark a{color:#93c5fd}.theme-dark .status{background:#334155;color:#e2e8f0;border-color:#64748b}.theme-dark .fresh{background:#14532d;color:#dcfce7}.theme-craft{background:#e8eddf;color:#243021}.theme-craft article{background:#faf9ed;border:2px solid #536547;border-radius:2px;box-shadow:4px 4px 0 #9da98e}.theme-craft header{border-bottom:4px solid #557b39}.theme-craft h1{letter-spacing:1px}.theme-craft .site-logo{image-rendering:pixelated;border-radius:0}.theme-craft header p,.theme-craft .hint,.theme-craft dt,.theme-craft footer,.theme-craft .time{color:#46553b}@media(max-width:480px){main{padding:24px 16px}h1{font-size:24px}.site-logo{width:48px;height:48px}}
</style></head><body class="theme-{{.Appearance.Theme}}"><main><header><div class="site-brand">{{if .Appearance.Logo}}<img class="site-logo" src="{{logo .Appearance.Logo}}" alt="站点 Logo" width="64" height="64">{{end}}<h1>{{.Appearance.Title}}</h1></div><p>{{.Appearance.Description}}</p></header>{{if not .Appearance.HideGlobe}}<section aria-label="服务器位置"><h2>服务器位置 · 3D 地球</h2><p class="hint">仅显示管理员明确公开的手动坐标，不代表网络连通性。选择下方位置可定位；支持拖动和方向键旋转。</p><div data-mx-globe="{{globe .Servers}}"></div><noscript>启用 JavaScript 可查看地球；下方资源列表仍可使用。</noscript></section>{{end}}<section class="grid" aria-label="服务器状态" style="margin-top:24px">{{range .Servers}}<article><h2>{{.Label}}</h2>{{with .Metadata}}<p class="hint">{{.Region}}{{if .Provider}} · {{.Provider}}{{end}}</p>{{if .ProviderURL}}<a href="{{.ProviderURL}}" target="_blank" rel="noopener noreferrer">服务商网站</a>{{end}}<p class="hint">到期：{{expiry .Expires}}{{if .Currency}}<br>费用：{{price .Price}} {{.Currency}} / {{cycle .Cycle}}{{end}}</p>{{end}}<span class="status {{.Status}}">{{status .Status}}</span><dl><div><dt>CPU 使用率</dt><dd>{{percent .CPU}}</dd></div><div><dt>内存使用率</dt><dd>{{percent .Memory}}</dd></div><div><dt>接收速率</dt><dd>{{rate .RXRate}}</dd></div><div><dt>发送速率</dt><dd>{{rate .TXRate}}</dd></div></dl><div class="time">采样：{{stamp .SampledAt}}</div>{{if .Probes}}<details><summary>Agent TCP 连通延迟</summary>{{range .Probes}}<p>{{.Name}}：{{latency .Milliseconds}}</p>{{end}}<p class="hint">TCP 建连测试，不代表 ICMP 丢包或代理连通性。</p></details>{{end}}{{if .ICMPProbes}}<details><summary>Agent ICMP 回包延迟</summary>{{range .ICMPProbes}}<p>{{.Name}}：{{latency .Milliseconds}}{{if .Error}}（{{probeError .Error}}）{{end}}</p>{{end}}<p class="hint">无权限或发送失败不计作丢包；超时也可能由目标过滤 ICMP 引起。</p></details>{{end}}<details><summary>查看 24 小时 CPU / 内存趋势</summary>{{chart .History}}</details></article>{{else}}<article><h2>暂无可展示的服务器</h2><p class="hint">请联系管理员检查分享设置。</p></article>{{end}}</section><footer>更新时间：{{stamp .GeneratedAt}}<br>状态表示资源采样结果；采样失败或数据过期不等同于服务器或代理服务离线。</footer></main><script src="/sub/status-globe.js" defer></script></body></html>`))

func fmtPercent(v float64) string { return fmt.Sprintf("%.1f%%", v) }
func fmtRate(v float64) string {
	for _, unit := range []string{"B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"} {
		if v < 1024 || unit == "TiB/s" {
			return fmt.Sprintf("%.1f %s", v, unit)
		}
		v /= 1024
	}
	return "—"
}

func (s *Server) sharedSeries(w http.ResponseWriter, r *http.Request, c monitorShare) {
	index, err := strconv.Atoi(r.URL.Query().Get("server"))
	hours := map[string]int{"1h": 1, "6h": 6, "24h": 24}[r.URL.Query().Get("range")]
	if err != nil || index < 0 || index >= len(c.Servers) || hours == 0 {
		problem(w, 400, "server 必须为状态接口返回的 index，range 为 1h、6h 或 24h")
		return
	}
	manager, e := s.remoteManager()
	if e != nil {
		problem(w, 503, "暂不可用")
		return
	}
	if _, e = manager.Record(c.Servers[index].ID); e != nil {
		problem(w, 404, "服务器已移除")
		return
	}
	if method := r.URL.Query().Get("metric"); method == "tcp" || method == "icmp" {
		s.probeMu.Lock()
		history, err := s.readProbes(c.Servers[index].ID)
		s.probeMu.Unlock()
		if err != nil {
			problem(w, 503, "历史记录暂不可用")
			return
		}
		points := []netprobe.Result{}
		cutoff := s.now().Add(-time.Duration(hours) * time.Hour).Unix()
		for _, p := range history.Points {
			if p.Time >= cutoff && (p.Method == method || p.Method == "" && method == "tcp") {
				points = append(points, p)
			}
		}
		respond(w, 200, map[string]any{"label": c.Servers[index].Label, "method": method, "source": "agent", "points": points, "generatedAt": s.now().Unix()})
		return
	}
	state, e := s.history.Read(c.Servers[index].ID, s.now())
	if e != nil {
		problem(w, 503, "历史记录暂不可用")
		return
	}
	points := []monitorhistory.Point{}
	cutoff := s.now().Add(-time.Duration(hours) * time.Hour).Unix()
	for _, p := range state.Points {
		if p.Time >= cutoff {
			points = append(points, p)
		}
	}
	respond(w, 200, map[string]any{"label": c.Servers[index].Label, "enabled": state.Enabled, "generatedAt": s.now().Unix(), "points": points})
}

// Only numeric coordinates enter this generated SVG. Missing samples break lines.
func historyChart(points []monitorhistory.Point) template.HTML {
	if len(points) == 0 {
		return template.HTML(`<p class="hint">暂无历史记录，请等待后台采样。</p>`)
	}
	end := points[len(points)-1].Time
	start := end - 86400
	var out strings.Builder
	out.WriteString(`<svg viewBox="0 0 300 120" role="img" aria-label="24小时资源趋势：橙色 CPU，绿色内存，范围0到100%"><path d="M0 10H300 M0 110H300" stroke="#d7c9bb" fill="none"/>`)
	for series, color := range []string{"#c95723", "#238454"} {
		path := ""
		last := int64(0)
		for _, p := range points {
			value := p.CPU
			if series == 1 {
				value = p.Memory
			}
			if !p.OK || value == nil || p.Time < start {
				last = 0
				continue
			}
			v := *value
			if v < 0 {
				v = 0
			}
			if v > 100 {
				v = 100
			}
			command := "L"
			if last == 0 || p.Time-last > 120 {
				command = "M"
			}
			path += fmt.Sprintf("%s%.2f %.2f ", command, float64(p.Time-start)*300/86400, 110-v)
			last = p.Time
		}
		fmt.Fprintf(&out, `<path d="%s" stroke="%s" stroke-width="2" fill="none"/>`, path, color)
	}
	out.WriteString(`</svg><p class="hint">橙色 CPU · 绿色内存 · 0–100%，缺失采样不连线</p>`)
	return template.HTML(out.String())
}
