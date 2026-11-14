package web

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

type notificationConfig struct {
	Renewal      bool   `json:"renewal"`
	RenewalUsers string `json:"renewalUsers"`
	Enabled      bool   `json:"enabled"`
	ChatID       string `json:"chatId"`
	SealedToken  string `json:"sealedToken,omitempty"`
	Monitor      bool   `json:"monitor"`
	Traffic      bool   `json:"traffic"`
	Expiry       bool   `json:"expiry"`
	Days         int    `json:"days"`
	Percent      int    `json:"percent"`
	Failures     int    `json:"failures"`
	Daily        bool   `json:"daily"`
	DailyHour    int    `json:"dailyHour"`
	Probes       bool   `json:"probes"`
	LatencyMS    int    `json:"latencyMs"`
	LossPercent  int    `json:"lossPercent"`
}
type notificationEvent struct {
	RenewalResult string           `json:"renewalResult,omitempty"`
	Renewal       *telegramRenewal `json:"renewal,omitempty"`
	Key           string           `json:"key,omitempty"`
	Time          int64            `json:"time"`
	Text          string           `json:"text"`
	Status        string           `json:"status"`
	Attempts      int              `json:"attempts"`
	Next          int64            `json:"next"`
	Error         string           `json:"error,omitempty"`
}
type notificationState struct {
	CallbackReceiptError string              `json:"callbackReceiptError,omitempty"`
	CallbackOffset       int64               `json:"callbackOffset,omitempty"`
	CallbackNext         int64               `json:"callbackNext,omitempty"`
	CallbackError        string              `json:"callbackError,omitempty"`
	LastDaily            string              `json:"lastDaily,omitempty"`
	Config               notificationConfig  `json:"config"`
	Active               map[string]string   `json:"active"`
	Events               []notificationEvent `json:"events"`
}

func (s *Server) readNotifications() (notificationState, error) {
	n := notificationState{Config: notificationConfig{Monitor: true, Traffic: true, Expiry: true, Days: 7, Percent: 90, Failures: 3, DailyHour: 1, LatencyMS: 300, LossPercent: 20}, Active: map[string]string{}, Events: []notificationEvent{}}
	b, e := os.ReadFile(filepath.Join(s.options.Root, "notifications.json"))
	if os.IsNotExist(e) {
		return n, nil
	}
	if e != nil {
		return n, e
	}
	e = json.Unmarshal(b, &n)
	if n.Active == nil {
		n.Active = map[string]string{}
	}
	return n, e
}
func (s *Server) saveNotifications(n notificationState) error {
	b, e := json.Marshal(n)
	if e != nil {
		return e
	}
	f, e := os.CreateTemp(s.options.Root, ".notifications-*")
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
	return os.Rename(f.Name(), filepath.Join(s.options.Root, "notifications.json"))
}

var notificationTokenPattern = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{20,100}$`)
var notificationChatPattern = regexp.MustCompile(`^-?[0-9]{1,20}$`)

func (s *Server) notificationRoute(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path == "/admin/api/notifications/daily-preview" {
		if r.Method != "GET" {
			problem(w, 405, "请求方法不支持")
			return true
		}
		message, e := s.notificationDailyReport(s.now())
		if e != nil {
			problem(w, 500, "日报数据读取失败")
		} else {
			respond(w, 200, map[string]string{"text": message})
		}
		return true
	}
	if r.URL.Path != "/admin/api/notifications" {
		return false
	}
	s.notificationMu.Lock()
	defer s.notificationMu.Unlock()
	n, e := s.readNotifications()
	if e != nil {
		problem(w, 500, "通知配置读取失败")
		return true
	}
	switch r.Method {
	case "GET":
	case "PUT":
		var input struct {
			Renewal      *bool   `json:"renewal"`
			RenewalUsers *string `json:"renewalUsers"`
			Enabled      bool    `json:"enabled"`
			ChatID       string  `json:"chatId"`
			Token        string  `json:"token"`
			ClearToken   bool    `json:"clearToken"`
			Monitor      bool    `json:"monitor"`
			Traffic      bool    `json:"traffic"`
			Expiry       bool    `json:"expiry"`
			Days         int     `json:"days"`
			Percent      int     `json:"percent"`
			Failures     int     `json:"failures"`
			Daily        *bool   `json:"daily"`
			DailyHour    *int    `json:"dailyHour"`
			Probes       *bool   `json:"probes"`
			LatencyMS    *int    `json:"latencyMs"`
			LossPercent  *int    `json:"lossPercent"`
		}
		if readJSON(w, r, &input) != nil {
			return true
		}
		input.Token = strings.TrimSpace(input.Token)
		input.ChatID = strings.TrimSpace(input.ChatID)
		if input.Days < 1 || input.Days > 30 || input.Percent < 1 || input.Percent > 100 || input.Failures < 2 || input.Failures > 20 || (input.ChatID != "" && !notificationChatPattern.MatchString(input.ChatID)) || (input.Token != "" && !notificationTokenPattern.MatchString(input.Token)) {
			problem(w, 400, "请检查 Token、数字 Chat ID、提前天数（1–30）、流量阈值（1–100）和连续失败次数（2–20）")
			return true
		}
		sealed := n.Config.SealedToken
		if input.ClearToken {
			sealed = ""
		}
		if input.Token != "" {
			m, err := s.remoteManager()
			if err != nil {
				problem(w, 500, "通知凭据保存失败")
				return true
			}
			sealed, err = m.SealUser(map[string]any{"token": input.Token})
			if err != nil {
				problem(w, 500, "通知凭据加密失败")
				return true
			}
		}
		if input.Enabled && (sealed == "" || input.ChatID == "") {
			problem(w, 400, "启用通知需要 Bot Token 和 Chat ID")
			return true
		}
		next := notificationConfig{Enabled: input.Enabled, ChatID: input.ChatID, SealedToken: sealed, Monitor: input.Monitor, Traffic: input.Traffic, Expiry: input.Expiry, Days: input.Days, Percent: input.Percent, Failures: input.Failures, Daily: n.Config.Daily, DailyHour: n.Config.DailyHour, Probes: n.Config.Probes, LatencyMS: n.Config.LatencyMS, LossPercent: n.Config.LossPercent}
		next.Renewal, next.RenewalUsers = n.Config.Renewal, n.Config.RenewalUsers
		if input.Renewal != nil {
			next.Renewal = *input.Renewal
		}
		if input.RenewalUsers != nil {
			next.RenewalUsers = *input.RenewalUsers
		}
		if !next.Enabled || !next.Expiry {
			next.Renewal = false
		}
		users, err := normalizeRenewalUsers(next.RenewalUsers)
		if err != nil || (next.Renewal && users == "") {
			problem(w, 400, "续费按钮需要开启通知和到期提醒，并填写允许操作的数字 Telegram 用户 ID（最多 20 个）")
			return true
		}
		next.RenewalUsers = users
		if input.Daily != nil {
			next.Daily = *input.Daily
		}
		if input.DailyHour != nil {
			next.DailyHour = *input.DailyHour
		}
		if input.Probes != nil {
			next.Probes = *input.Probes
		}
		if input.LatencyMS != nil {
			next.LatencyMS = *input.LatencyMS
		}
		if input.LossPercent != nil {
			next.LossPercent = *input.LossPercent
		}
		if next.DailyHour < 0 || next.DailyHour > 23 || next.LatencyMS < 1 || next.LatencyMS > 60000 || next.LossPercent < 1 || next.LossPercent > 100 {
			problem(w, 400, "日报小时须为 UTC 0–23，延迟阈值 1–60000 毫秒，失败比例 1–100%")
			return true
		}
		// Cancel stale queued messages when the recipient or alert policy changes.
		if next != n.Config || !next.Enabled {
			n.CallbackNext, n.CallbackError, n.CallbackReceiptError = 0, "", ""
			if next.SealedToken != n.Config.SealedToken {
				n.CallbackOffset = 0
			}
			for i := range n.Events {
				n.Events[i].Renewal = nil
			}
			for i := range n.Events {
				if n.Events[i].Status == "pending" {
					n.Events[i].Status = "cancelled"
				}
			}
		}
		n.Config = next
		if e = s.saveNotifications(n); e != nil {
			problem(w, 500, "通知配置保存失败")
			return true
		}
	default:
		problem(w, 405, "请求方法不支持")
		return true
	}
	public := n.Config
	public.SealedToken = ""
	events := append([]notificationEvent{}, n.Events...)
	for i := range events {
		events[i].Renewal = nil
	}
	respond(w, 200, map[string]any{"config": public, "tokenConfigured": n.Config.SealedToken != "", "events": events, "callbackError": strings.TrimSpace(n.CallbackError + "\n" + n.CallbackReceiptError)})
	return true
}

// Only reads existing observations; notification polling never contacts a node.
func (s *Server) notificationConditions(c notificationConfig, now time.Time) (map[string]string, error) {
	out := map[string]string{}
	manager, e := s.remoteManager()
	if e != nil {
		return nil, e
	}
	rows, e := manager.List()
	if e != nil {
		return nil, e
	}
	for _, row := range rows {
		id, _ := row["id"].(string)
		name, _ := row["name"].(string)
		if name == "" {
			name = id
		}
		if c.Monitor && probeLinked(row) {
			out["unknown:"+id] = "1"
		}
		if c.Monitor && !probeLinked(row) {
			h, e := s.history.Read(id, now)
			if e != nil {
				return nil, e
			}
			if h.Enabled && len(h.Points) >= c.Failures {
				recent := h.Points[len(h.Points)-c.Failures:]
				bad := true
				for _, p := range recent {
					if p.OK || p.Time < now.Add(-time.Duration(c.Failures*90)*time.Second).Unix() {
						bad = false
					}
				}
				// Stale data is unknown, never a recovery or an offline assertion.
				if recent[len(recent)-1].Time < now.Add(-120*time.Second).Unix() {
					out["unknown:"+id] = "1"
				} else if bad {
					out["monitor:"+id] = "服务器「" + name + "」连续监控采样失败，请检查连接；不代表代理服务一定离线。"
				} else if recent[len(recent)-1].OK {
					out["healthy:"+id] = "1"
				} else if !recent[len(recent)-1].OK {
					out["unknown:"+id] = "1"
				}
			} else if h.Enabled {
				out["unknown:"+id] = "1"
			}
		}
		if c.Probes && !probeLinked(row) {
			h, e := s.history.Read(id, now)
			if e != nil {
				return nil, e
			}
			if h.Enabled {
				s.probeMu.Lock()
				probes, e := s.readProbes(id)
				s.probeMu.Unlock()
				if e != nil {
					return nil, e
				}
				for k, v := range notificationProbeConditions(id, name, probes.Points, c, now) {
					out[k] = v
				}
			}
		}
		if c.Expiry {
			m, e := s.readMetadata(id)
			if e != nil {
				return nil, e
			}
			if m.Expires != "" {
				t, e := time.Parse("2006-01-02", m.Expires)
				if e == nil && t.Before(now.Add(time.Duration(c.Days)*24*time.Hour)) {
					out["server-expiry:"+id] = fmt.Sprintf("服务器「%s」续费提醒：到期日期 %s（UTC），请确认续费。", name, m.Expires)
				}
			}
		}
	}
	if c.Traffic || c.Expiry {
		profiles, e := s.repository.Profiles()
		if e != nil {
			return nil, e
		}
		for _, p := range profiles {
			id, _ := p["id"].(string)
			name, _ := p["name"].(string)
			state, e := s.repository.State(id)
			if e != nil {
				return nil, e
			}
			t, e := config.TrafficInfo(state, now)
			if e != nil {
				return nil, e
			}
			if t["configured"] != true {
				continue
			}
			percent, _ := t["percent"].(float64)
			if c.Traffic && (percent >= float64(c.Percent) || t["exhausted"] == true) {
				out["traffic:"+id] = fmt.Sprintf("订阅「%s」流量已达到 %d%% 提醒阈值，请检查剩余额度。", name, c.Percent)
			}
			if exp, ok := t["expire"].(int64); c.Expiry && ok && exp < now.Add(time.Duration(c.Days)*24*time.Hour).Unix() {
				out["subscription-expiry:"+id] = fmt.Sprintf("订阅「%s」到期提醒：%s（UTC）。", name, time.Unix(exp, 0).UTC().Format("2006-01-02 15:04"))
			}
		}
	}
	return out, nil
}
func notificationReconcile(n *notificationState, current map[string]string, now time.Time) {
	// A renewed or edited expiry invalidates queued reminders before delivery.
	for i := range n.Events {
		event := &n.Events[i]
		if event.Status != "pending" {
			continue
		}
		if strings.HasPrefix(event.Key, "server-expiry:") || strings.HasPrefix(event.Key, "subscription-expiry:") {
			if current[event.Key] != event.Text {
				event.Status = "cancelled"
			}
		} else if event.Key == "" {
			// Older queues had no keys: only cancel a known old expiry message when
			// no current condition still needs that exact message.
			oldExpiry, stillNeeded := false, false
			for key, text := range n.Active {
				if text == event.Text && (strings.HasPrefix(key, "server-expiry:") || strings.HasPrefix(key, "subscription-expiry:")) {
					oldExpiry = true
				}
			}
			for _, text := range current {
				if text == event.Text {
					stillNeeded = true
				}
			}
			if oldExpiry && !stillNeeded {
				event.Status = "cancelled"
			}
		}
	}
	keys := make([]string, 0, len(current))
	for k := range current {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	add := func(key, message string) {
		n.Events = append(n.Events, notificationEvent{Key: key, Time: now.Unix(), Text: message, Status: "pending", Next: now.Unix()})
	}
	for _, key := range keys {
		if strings.HasPrefix(key, "unknown:") || strings.HasPrefix(key, "healthy:") {
			continue
		}
		if n.Active[key] != current[key] {
			add(key, current[key])
		}
	}
	oldKeys := make([]string, 0, len(n.Active))
	for key := range n.Active {
		oldKeys = append(oldKeys, key)
	}
	sort.Strings(oldKeys)
	for _, key := range oldKeys {
		if strings.HasPrefix(key, "probe-") && current[key] == "" && n.Config.Probes {
			if current["unknown:"+key] != "" {
				current[key] = n.Active[key]
			} else if current["healthy:"+key] != "" {
				add("", "探测恢复通知（以下原告警已解除）："+n.Active[key])
			}
		}
		if strings.HasPrefix(key, "monitor:") && current[key] == "" {
			if current["unknown:"+strings.TrimPrefix(key, "monitor:")] != "" {
				current[key] = n.Active[key]
			} else if n.Config.Monitor && current["healthy:"+strings.TrimPrefix(key, "monitor:")] != "" {
				add("", "监控采样恢复："+strings.TrimSuffix(n.Active[key], "连续监控采样失败，请检查连接；不代表代理服务一定离线。"))
			}
		}
	}
	for key := range current {
		if strings.HasPrefix(key, "unknown:") || strings.HasPrefix(key, "healthy:") {
			delete(current, key)
		}
	}
	n.Active = current
	if len(n.Events) > 200 {
		n.Events = n.Events[len(n.Events)-200:]
	}
}

// HTTP errors are deliberately generic: request URLs contain the bot secret.
func sendTelegram(ctx context.Context, client *http.Client, token, chat, message string, markup ...any) (int, string) {
	payload := map[string]any{"chat_id": chat, "text": message, "disable_web_page_preview": true}
	if len(markup) > 0 && markup[0] != nil {
		payload["reply_markup"] = markup[0]
	}
	body, _ := json.Marshal(payload)
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewReader(body))
	if e != nil {
		return 60, "通知请求创建失败"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(req)
	if e != nil {
		return 60, "Telegram 连接失败"
	}
	defer resp.Body.Close()
	var result struct {
		OK         bool `json:"ok"`
		Parameters struct {
			RetryAfter int `json:"retry_after"`
		} `json:"parameters"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 65536)).Decode(&result) != nil {
		return 60, "Telegram 响应无效"
	}
	if resp.StatusCode == 200 && result.OK {
		return 0, ""
	}
	delay := result.Parameters.RetryAfter
	if delay < 60 {
		delay = 60
	}
	if delay > 86400 {
		delay = 86400
	}
	return delay, fmt.Sprintf("Telegram 返回 HTTP %d", resp.StatusCode)
}
func (s *Server) pollNotifications(ctx context.Context) {
	s.notificationMu.Lock()
	defer s.notificationMu.Unlock()
	n, e := s.readNotifications()
	if e != nil || !n.Config.Enabled {
		return
	}
	now := s.now()
	current, e := s.notificationConditions(n.Config, now)
	if e != nil {
		return
	}
	notificationReconcile(&n, current, now)
	if n.Config.Daily && now.UTC().Hour() >= n.Config.DailyHour {
		date := now.UTC().AddDate(0, 0, -1).Format("2006-01-02")
		if n.LastDaily < date {
			if message, e := s.notificationDailyReport(now); e == nil {
				n.Events = append(n.Events, notificationEvent{Time: now.Unix(), Text: message, Status: "pending", Next: now.Unix()})
				n.LastDaily = date
			}
		}
	}
	if len(n.Events) > 200 {
		n.Events = n.Events[len(n.Events)-200:]
	}
	s.prepareTelegramRenewals(&n, now)
	// Persist intent before sending; a crash after delivery can cause one duplicate.
	if s.saveNotifications(n) != nil {
		return
	}
	for i := range n.Events {
		event := &n.Events[i]
		if event.Status != "pending" || event.Next > now.Unix() {
			continue
		}
		manager, e := s.remoteManager()
		if e != nil {
			return
		}
		secret, e := manager.OpenUser(n.Config.SealedToken)
		if e != nil {
			return
		}
		token, _ := secret["token"].(string)
		call, cancel := context.WithTimeout(ctx, 10*time.Second)
		delay, message := sendTelegram(call, &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, token, n.Config.ChatID, event.Text, renewalKeyboard(event.Renewal))
		cancel()
		event.Attempts++
		event.Error = message
		if message == "" {
			event.Status = "sent"
		} else if event.Attempts >= 8 {
			event.Status = "failed"
		} else {
			backoff := 30 * (1 << event.Attempts)
			if delay < backoff {
				delay = backoff
			}
			event.Next = now.Add(time.Duration(delay) * time.Second).Unix()
		}
		if s.saveNotifications(n) != nil {
			log.Print("notification delivery state save failed")
		}
		break
	}
}
