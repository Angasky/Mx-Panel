package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Nonces are stored with a bounded notification event, never exposed by admin GET.
// Metadata revisions make a replay harmless even after a crash between files.
type telegramRenewal struct {
	Server       string `json:"server"`
	Revision     string `json:"revision"`
	Previous     string `json:"previous"`
	Next         string `json:"next"`
	Nonce        string `json:"nonce"`
	Confirm      string `json:"confirm,omitempty"`
	User         int64  `json:"user,omitempty"`
	Until        int64  `json:"until"`
	ConfirmUntil int64  `json:"confirmUntil,omitempty"`
	Done         bool   `json:"done,omitempty"`
}

func normalizeRenewalUsers(raw string) (string, error) {
	fields := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\r' || r == '\t' })
	if len(fields) > 20 {
		return "", errors.New("too many users")
	}
	out := []string{}
	seen := map[string]bool{}
	for _, f := range fields {
		id, e := strconv.ParseInt(f, 10, 64)
		if e != nil || id <= 0 || id > 1<<52 {
			return "", errors.New("invalid user")
		}
		idText := strconv.FormatInt(id, 10)
		if !seen[idText] {
			out = append(out, idText)
			seen[idText] = true
		}
	}
	return strings.Join(out, ","), nil
}
func renewalNonce() (string, error) {
	var b [16]byte
	_, e := rand.Read(b[:])
	return hex.EncodeToString(b[:]), e
}
func renewalKeyboard(r *telegramRenewal) any {
	if r == nil || r.Done {
		return nil
	}
	return map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "我已续费 · 预览登记", "callback_data": "mxr:" + r.Nonce}}}}
}
func (s *Server) prepareTelegramRenewals(n *notificationState, now time.Time) {
	if !n.Config.Renewal || !n.Config.Expiry {
		return
	}
	s.metadataMu.Lock()
	defer s.metadataMu.Unlock()
	for i := range n.Events {
		e := &n.Events[i]
		if e.Status != "pending" || e.Renewal != nil || !strings.HasPrefix(e.Key, "server-expiry:") {
			continue
		}
		id := strings.TrimPrefix(e.Key, "server-expiry:")
		m, err := s.readMetadata(id)
		if err != nil {
			continue
		}
		v, err := previewRenewal(m, "expiry", now)
		if err != nil {
			continue
		}
		nonce, err := renewalNonce()
		if err != nil {
			continue
		}
		e.Renewal = &telegramRenewal{Server: id, Revision: v.Revision, Previous: v.Previous, Next: v.Next, Nonce: nonce, Until: now.Add(7 * 24 * time.Hour).Unix()}
	}
}

type telegramCallback struct {
	ID   string `json:"id"`
	Data string `json:"data"`
	From struct {
		ID  int64 `json:"id"`
		Bot bool  `json:"is_bot"`
	} `json:"from"`
	Message *struct {
		ID   int64 `json:"message_id"`
		Chat struct {
			ID int64 `json:"id"`
		} `json:"chat"`
	} `json:"message"`
}
type telegramUpdate struct {
	ID       int64             `json:"update_id"`
	Callback *telegramCallback `json:"callback_query"`
}
type telegramReply struct {
	Text   string
	Markup any
	Edit   bool
}

// Caller holds notificationMu. No network calls while checking/mutating metadata.
func (s *Server) applyTelegramRenewal(n *notificationState, q telegramCallback) telegramReply {
	reject := func(text string) telegramReply { return telegramReply{Text: text} }
	if !n.Config.Enabled || !n.Config.Expiry || !n.Config.Renewal || q.Message == nil || q.Message.ID <= 0 || q.From.Bot || q.From.ID <= 0 || strconv.FormatInt(q.Message.Chat.ID, 10) != n.Config.ChatID {
		return reject("无权操作此续费提醒")
	}
	if !strings.Contains(","+n.Config.RenewalUsers+",", ","+strconv.FormatInt(q.From.ID, 10)+",") {
		return reject("当前用户未获续费登记授权")
	}
	if len(q.Data) != 36 {
		return reject("按钮无效，请在面板登记")
	}
	action, nonce := q.Data[:4], q.Data[4:]
	if action != "mxr:" && action != "mxc:" && action != "mxx:" {
		return reject("按钮无效")
	}
	var event *notificationEvent
	for i := range n.Events {
		r := n.Events[i].Renewal
		if r != nil && ((action == "mxr:" && r.Nonce == nonce) || (action != "mxr:" && r.Confirm != "" && r.Confirm == nonce)) {
			event = &n.Events[i]
			break
		}
	}
	if event == nil {
		return reject("按钮已失效，请在面板重新预览")
	}
	r := event.Renewal
	now := s.now()
	if r.Done {
		return reject("该次续费已登记，未重复延长")
	}
	if now.Unix() >= r.Until || event.Status == "cancelled" || event.Status == "failed" {
		return reject("提醒已过期，请在面板登记")
	}
	if action != "mxr:" && (q.From.ID != r.User || now.Unix() >= r.ConfirmUntil) {
		return reject("确认已过期或不是原操作用户，请重新预览")
	}
	if action == "mxx:" {
		r.Confirm = ""
		r.User = 0
		return telegramReply{Text: event.Text + "\n已取消本次登记。", Markup: renewalKeyboard(r), Edit: true}
	}
	manager, e := s.remoteManager()
	if e != nil {
		return reject("服务器数据不可用")
	}
	if _, e = manager.Record(r.Server); e != nil {
		return reject("服务器已不存在")
	}
	s.metadataMu.Lock()
	defer s.metadataMu.Unlock()
	m, e := s.readMetadata(r.Server)
	if e != nil {
		return reject("续费信息读取失败")
	}
	v, e := previewRenewal(m, "expiry", now)
	if e != nil || v.Revision != r.Revision {
		return reject("信息已改变或已登记，请到面板核对；未重复延长")
	}
	if action == "mxr:" {
		confirm, e := renewalNonce()
		if e != nil {
			return reject("暂时无法生成确认，请重试")
		}
		r.Confirm, r.User, r.ConfirmUntil = confirm, q.From.ID, now.Add(5*time.Minute).Unix()
		public := ""
		if m.Public {
			public = "\n此日期将随已开启的监控分享公开。"
		}
		return telegramReply{Text: fmt.Sprintf("%s\n\n登记预览（UTC）：%s → %s\n仅登记日期，不执行支付、不重置流量。请确认已在服务商完成续费；5 分钟内有效。%s", event.Text, v.Previous, v.Next, public), Edit: true, Markup: map[string]any{"inline_keyboard": [][]map[string]string{{{"text": "确认已付款 · 登记新日期", "callback_data": "mxc:" + confirm}}, {{"text": "取消", "callback_data": "mxx:" + confirm}}}}}
	}
	m.Expires = v.Next
	if e = s.writeMetadata(r.Server, m); e != nil {
		return reject("保存失败，请重试或在面板核对")
	}
	r.Done = true
	event.RenewalResult = fmt.Sprintf("Telegram 用户 %d 于 %s 登记：%s → %s（UTC）", q.From.ID, now.UTC().Format("2006-01-02 15:04:05"), v.Previous, v.Next)
	return telegramReply{Text: fmt.Sprintf("%s\n\n已登记续费：%s → %s（UTC）。未执行支付，未重置流量。", event.Text, v.Previous, v.Next), Edit: true, Markup: map[string]any{"inline_keyboard": [][]any{}}}
}

// Never return raw upstream errors: Telegram request URLs contain credentials.
func telegramRequest(ctx context.Context, client *http.Client, token, method string, payload any, out any) (int, string) {
	b, e := json.Marshal(payload)
	if e != nil {
		return 60, "Telegram 请求创建失败"
	}
	req, e := http.NewRequestWithContext(ctx, "POST", "https://api.telegram.org/bot"+token+"/"+method, bytes.NewReader(b))
	if e != nil {
		return 60, "Telegram 请求创建失败"
	}
	req.Header.Set("Content-Type", "application/json")
	resp, e := client.Do(req)
	if e != nil {
		return 60, "Telegram 连接失败"
	}
	defer resp.Body.Close()
	var body struct {
		OK         bool            `json:"ok"`
		Result     json.RawMessage `json:"result"`
		Parameters struct {
			Retry int `json:"retry_after"`
		} `json:"parameters"`
	}
	if e = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&body); e != nil {
		return 60, "Telegram 响应无效"
	}
	if resp.StatusCode != 200 || !body.OK {
		delay := max(60, min(86400, body.Parameters.Retry))
		if resp.StatusCode == 409 {
			return delay, "机器人存在 Webhook 或其他轮询程序，请使用专用机器人；面板不会删除 Webhook"
		}
		return delay, fmt.Sprintf("Telegram 返回 HTTP %d", resp.StatusCode)
	}
	if out != nil && json.Unmarshal(body.Result, out) != nil {
		return 60, "Telegram 数据无效"
	}
	return 0, ""
}
func (s *Server) pollTelegramRenewals(ctx context.Context) {
	s.notificationMu.Lock()
	n, e := s.readNotifications()
	s.notificationMu.Unlock()
	if e != nil || !n.Config.Enabled || !n.Config.Expiry || !n.Config.Renewal || n.CallbackNext > s.now().Unix() {
		return
	}
	cfg := n.Config
	manager, e := s.remoteManager()
	if e != nil {
		return
	}
	secret, e := manager.OpenUser(cfg.SealedToken)
	if e != nil {
		return
	}
	token, _ := secret["token"].(string)
	client := &http.Client{Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	call, cancel := context.WithTimeout(ctx, 8*time.Second)
	var updates []telegramUpdate
	delay, msg := telegramRequest(call, client, token, "getUpdates", map[string]any{"offset": n.CallbackOffset, "timeout": 0, "limit": 20, "allowed_updates": []string{"callback_query"}}, &updates)
	cancel()
	if len(updates) > 20 {
		delay, msg = 60, "Telegram 返回更新过多"
	}
	s.notificationMu.Lock()
	current, e := s.readNotifications()
	if e != nil || current.Config != cfg {
		s.notificationMu.Unlock()
		return
	}
	changed := current.CallbackError != msg || current.CallbackNext != 0
	current.CallbackError = msg
	if msg != "" {
		current.CallbackNext = s.now().Add(time.Duration(delay) * time.Second).Unix()
		s.saveNotifications(current)
		s.notificationMu.Unlock()
		return
	}
	current.CallbackNext = 0
	if changed && s.saveNotifications(current) != nil {
		s.notificationMu.Unlock()
		return
	}
	s.notificationMu.Unlock()
	for _, u := range updates {
		if ctx.Err() != nil {
			return
		}
		if u.ID < 0 || u.ID >= 1<<52 {
			continue
		}
		s.notificationMu.Lock()
		current, e = s.readNotifications()
		if e != nil || current.Config != cfg {
			s.notificationMu.Unlock()
			return
		}
		if u.ID < current.CallbackOffset {
			s.notificationMu.Unlock()
			continue
		}
		reply := telegramReply{}
		if u.Callback != nil {
			reply = s.applyTelegramRenewal(&current, *u.Callback)
		}
		current.CallbackOffset = u.ID + 1
		e = s.saveNotifications(current)
		s.notificationMu.Unlock()
		if e != nil {
			return
		}
		if u.Callback == nil {
			continue
		}
		q := u.Callback
		call, cancel = context.WithTimeout(ctx, 8*time.Second)
		// Inline callback acknowledgements expire quickly; editing the message is
		// the durable response even when Telegram rejects an old acknowledgement.
		ack := "请查看消息中的登记结果"
		if !reply.Edit {
			ack = reply.Text
		}
		telegramRequest(call, client, token, "answerCallbackQuery", map[string]any{"callback_query_id": q.ID, "text": ack, "show_alert": !reply.Edit}, nil)
		editError := ""
		if reply.Edit && q.Message != nil {
			_, editError = telegramRequest(call, client, token, "editMessageText", map[string]any{"chat_id": cfg.ChatID, "message_id": q.Message.ID, "text": reply.Text, "reply_markup": reply.Markup, "disable_web_page_preview": true}, nil)
		}
		cancel()
		if reply.Edit {
			s.notificationMu.Lock()
			latest, err := s.readNotifications()
			if err == nil && latest.Config == cfg {
				latest.CallbackReceiptError = ""
				if editError != "" {
					latest.CallbackReceiptError = "回执编辑失败，请在面板核对到期日期：" + editError
				}
				s.saveNotifications(latest)
			}
			s.notificationMu.Unlock()
		}
	}
}
