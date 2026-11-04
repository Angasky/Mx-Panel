// Package subscriptions coordinates durable ownership, remote users and billing.
package subscriptions

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type Record = map[string]any
type Backend interface {
	Record(string) (remote.Record, error)
	Inbounds(context.Context, string) (remote.Record, error)
	SubscriptionUser(context.Context, string, remote.Record, string, remote.Record) (remote.Record, error)
	SealUser(remote.Record) (string, error)
	OpenUser(string) (remote.Record, error)
}
type Controller struct {
	Repository  *config.Repository
	Backend     Backend
	mu          sync.Mutex
	locks       map[string]chan struct{}
	serverLocks map[string]chan struct{}
	started     atomic.Bool
	Now         func() time.Time
}

func New(repository *config.Repository, backend Backend) *Controller {
	return &Controller{Repository: repository, Backend: backend, locks: map[string]chan struct{}{}, Now: time.Now}
}
func text(v any) string {
	switch n := v.(type) {
	case string:
		return n
	case int:
		return strconv.Itoa(n)
	case int64:
		return strconv.FormatInt(n, 10)
	case json.Number:
		return string(n)
	}
	return ""
}
func number(v any, defaultValue int64) (int64, error) {
	if v == nil {
		return defaultValue, nil
	}
	switch v.(type) {
	case int, int64, json.Number:
	default:
		return 0, errors.New("计量字段必须为整数")
	}
	n, e := strconv.ParseInt(text(v), 10, 64)
	if e != nil || n < 0 {
		return 0, errors.New("计量字段超出范围")
	}
	return n, nil
}
func objects(v any) []Record {
	out := []Record{}
	if list, ok := v.([]any); ok {
		for _, v := range list {
			if row, ok := v.(map[string]any); ok {
				out = append(out, row)
			}
		}
	}
	return out
}
func traffic(record Record) Record {
	if t, ok := record["traffic"].(map[string]any); ok {
		return t
	}
	return Record{}
}
func usage(record Record) (billing.Usage, error) {
	t := traffic(record)
	u := billing.Usage{Enabled: t["enabled"] == true, Enforce: t["enforce"] == true, Revoked: record["accessRevoked"] == true}
	var err error
	if u.Upload, err = number(t["upload"], 0); err != nil {
		return u, err
	}
	if u.Download, err = number(t["download"], 0); err != nil {
		return u, err
	}
	for _, key := range []string{"total", "expire"} {
		if t[key] != nil {
			n, e := number(t[key], 0)
			if e != nil {
				return u, e
			}
			if key == "total" {
				u.Total = &n
			} else {
				u.Expire = &n
			}
		}
	}
	return u, nil
}
func (c *Controller) lock(ctx context.Context, id string) (func(), error) {
	return c.operationLock(ctx, id, false)
}
func (c *Controller) lockServer(ctx context.Context, id string) (func(), error) {
	return c.operationLock(ctx, id, true)
}
func (c *Controller) operationLock(ctx context.Context, id string, server bool) (func(), error) {
	if id == "" {
		id = "clash"
	}
	c.mu.Lock()
	guards := c.locks
	limit := 256
	if server {
		if c.serverLocks == nil {
			c.serverLocks = map[string]chan struct{}{}
		}
		guards = c.serverLocks
		limit = 1024
	}
	guard := guards[id]
	if guard == nil {
		if len(guards) >= limit {
			c.mu.Unlock()
			return nil, errors.New("操作对象数量过多")
		}
		guard = make(chan struct{}, 1)
		guards[id] = guard
	}
	c.mu.Unlock()
	select {
	case guard <- struct{}{}:
		return func() { <-guard }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
func newToken() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw), nil
}
func bindingKey(b Record) string {
	return fmt.Sprint(b["serverId"]) + "/" + fmt.Sprint(b["inboundId"]) + "/" + text(b["userEmail"]) + "/" + text(b["userHash"])
}
func sameBinding(record, b Record) (Record, error) {
	for _, candidate := range objects(record["remoteNodes"]) {
		if bindingKey(candidate) == bindingKey(b) && candidate["identityHash"] == b["identityHash"] && (candidate["status"] == "active" || candidate["status"] == "provisioning") {
			return candidate, nil
		}
	}
	return nil, errors.New("订阅用户归属已变化")
}
func (c *Controller) updateBinding(profile string, b Record, change func(Record, Record) error) error {
	return c.Repository.UpdateState(profile, func(record Record) error {
		current, err := sameBinding(record, b)
		if err != nil {
			return err
		}
		return change(record, current)
	})
}

func (c *Controller) Batch(ctx context.Context, profile, server string, ids []int) (Record, error) {
	if !c.started.Load() {
		return nil, errors.New("独立用户后台计量尚未启动")
	}
	if server == "" || len(ids) < 1 || len(ids) > 50 {
		return nil, errors.New("请选择服务器和 1–50 个入站")
	}
	seen := map[int]bool{}
	for _, id := range ids {
		if id <= 0 || seen[id] {
			return nil, errors.New("入站 ID 无效或重复")
		}
		seen[id] = true
	}
	serverUnlock, err := c.lockServer(ctx, server)
	if err != nil {
		return nil, err
	}
	defer serverUnlock()
	if err = c.Repository.CheckInboundAvailable(server, ids...); err != nil {
		return nil, err
	}
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	record, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	if err = c.preflight(record, server); err != nil {
		return nil, err
	}
	snapshot, err := c.Backend.Inbounds(ctx, server)
	if err != nil {
		return nil, err
	}
	rawRows := snapshot["inbounds"]
	if snapshot["readOnly"] == true {
		rawRows = snapshot["provisionInbounds"]
	}
	rows := map[int]Record{}
	for _, row := range objects(rawRows) {
		id, _ := strconv.Atoi(text(row["id"]))
		rows[id] = row
	}
	results := []any{}
	succeeded, added, existing := 0, 0, 0
	for _, id := range ids {
		item := Record{"inboundId": id, "name": ""}
		row := rows[id]
		if row != nil {
			item["name"] = row["remark"]
		}
		result, e := c.provision(ctx, profile, server, row)
		if e != nil {
			item["ok"] = false
			item["error"] = e.Error()
		} else {
			item["ok"] = true
			item["added"] = result["added"]
			item["existing"] = result["existing"]
			for _, key := range []string{"runtimeVerified", "runtimeRepaired", "warning"} {
				if value, exists := result[key]; exists {
					item[key] = value
				}
			}
			succeeded++
			added += result["added"].(int)
			existing += result["existing"].(int)
		}
		results = append(results, item)
	}
	info, err := c.Info(profile)
	if err != nil {
		return nil, err
	}
	return Record{"results": results, "succeeded": succeeded, "failed": len(ids) - succeeded, "added": added, "existing": existing, "traffic": info}, nil
}
func (c *Controller) preflight(record Record, server string) error {
	u, err := usage(record)
	if err != nil {
		return err
	}
	u.Enabled = true
	u.Enforce = true
	if u.Blocked(c.Now()) {
		return errors.New("订阅已到期或流量用尽，请先续期")
	}
	t := traffic(record)
	speed, err := number(t["speedMbps"], 0)
	if err != nil || speed != 0 {
		return errors.New("共用用户暂不支持按用户限速")
	}
	for _, b := range objects(record["remoteNodes"]) {
		if (b["status"] == "active" || b["status"] == "provisioning") && b["scope"] != "user" {
			return errors.New("订阅仍有旧版入站绑定，请先迁移用户计量")
		}
	}
	s, err := c.Backend.Record(server)
	if err != nil {
		return err
	}
	kind := text(s["installType"])
	if kind == "" {
		kind = "3x-ui"
	}
	if kind != "3x-ui" && kind != "x-ui" && kind != "x-panel" && kind != "xray" && kind != "sing-box" {
		return errors.New("服务器类型不支持独立用户创建")
	}
	return nil
}
func (c *Controller) provision(ctx context.Context, profile, server string, row Record) (Record, error) {
	if row == nil {
		return nil, errors.New("远端入站不存在")
	}
	if row["enable"] == false {
		return nil, errors.New("入站已停用")
	}
	record, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	if err = c.preflight(record, server); err != nil {
		return nil, err
	}
	var binding Record
	for _, b := range objects(record["remoteNodes"]) {
		if b["serverId"] == server && text(b["inboundId"]) == text(row["id"]) && (b["status"] == "active" || b["status"] == "provisioning") {
			if binding != nil {
				return nil, errors.New("当前入站存在重复的有效归属记录，请先核对")
			}
			binding = b
		}
	}
	var client Record
	if binding == nil {
		client, err = remote.NewUser(row)
		if err != nil {
			return nil, err
		}
		endpoint, e := remote.EndpointIdentity(row)
		if e != nil {
			return nil, e
		}
		hash, e := remote.UserIdentity(client)
		if e != nil {
			return nil, e
		}
		sealed, e := c.Backend.SealUser(client)
		if e != nil {
			return nil, e
		}
		operation, e := newToken()
		if e != nil {
			return nil, e
		}
		units, e := number(traffic(record)["multiplierUnits"], 1000)
		if e != nil || units > 100000 {
			return nil, errors.New("节点倍率无效")
		}
		binding = Record{"scope": "user", "serverId": server, "inboundId": row["id"], "identityHash": endpoint, "userHash": hash, "userEmail": client["email"], "pendingUser": sealed, "operationId": operation, "name": row["remark"], "port": row["port"], "status": "provisioning", "boundAt": c.Now().Unix(), "up": int64(0), "down": int64(0), "counterSource": "pending", "multiplierUnits": units, "error": ""}
		// Limits are durable before the first remote grant. They remain enabled
		// on partial failure, so successfully created users stay accountable.
		err = c.Repository.UpdateState(profile, func(p Record) error {
			t := traffic(p)
			t["enabled"] = true
			t["enforce"] = true
			for _, k := range []string{"upload", "download", "rawUpload", "rawDownload"} {
				if t[k] == nil {
					t[k] = int64(0)
				}
			}
			p["traffic"] = t
			return nil
		})
		if err != nil {
			return nil, err
		}
		binding, err = c.Repository.BeginOwnership(profile, binding)
		if err != nil {
			return nil, err
		}
	} else {
		err = c.Repository.UpdateState(profile, func(p Record) error {
			t := traffic(p)
			t["enabled"] = true
			t["enforce"] = true
			p["traffic"] = t
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if binding["scope"] != "user" {
		return nil, errors.New("此入站仍有旧版绑定")
	}
	if _, err = remote.FindUser(row, binding, binding["status"] == "provisioning"); err != nil {
		return nil, err
	}
	if token := text(binding["pendingUser"]); token != "" {
		client, err = c.Backend.OpenUser(token)
		if err != nil {
			return nil, err
		}
	} else {
		client = nil
	}
	if text(binding["operationId"]) == "" {
		token, e := newToken()
		if e != nil {
			return nil, e
		}
		err = c.updateBinding(profile, binding, func(_ Record, b Record) error { b["operationId"] = token; return nil })
		if err != nil {
			return nil, err
		}
		binding["operationId"] = token
	}
	serverRecord, err := c.Backend.Record(server)
	if err != nil {
		return nil, err
	}
	op := "read"
	if serverRecord["installType"] == "x-panel" || row["protocol"] == "hysteria" || row["protocol"] == "hysteria2" {
		op = "verify"
	}
	if client != nil {
		op = "add"
	}
	response, err := c.Backend.SubscriptionUser(ctx, server, binding, op, client)
	if err != nil {
		message := "远端用户操作待核对；身份已保留，请在同一入站重试"
		detail := err.Error()
		for _, key := range []string{"id", "password", "auth", "subId"} {
			if secret := text(client[key]); secret != "" {
				detail = strings.ReplaceAll(detail, secret, "[已隐藏]")
			}
		}
		if len(detail) > 350 {
			detail = detail[:350]
		}
		message += "。原因：" + detail
		_ = c.updateBinding(profile, binding, func(_ Record, b Record) error { b["error"] = message; return nil })
		return nil, errors.New(message)
	}
	fresh, ok := response["inbound"].(map[string]any)
	if !ok {
		return nil, errors.New("面板未返回核验后的入站")
	}
	owned, err := remote.FindUser(fresh, binding, false)
	if err != nil {
		return nil, err
	}
	settings := Record{}
	switch model := fresh["settings"].(type) {
	case map[string]any:
		for k, v := range model {
			settings[k] = v
		}
	case string:
		decoder := json.NewDecoder(strings.NewReader(model))
		decoder.UseNumber()
		if decoder.Decode(&settings) != nil {
			return nil, errors.New("用户配置格式无效")
		}
	}
	settings["clients"] = []any{owned}
	selected := Record{}
	for k, v := range fresh {
		selected[k] = v
	}
	selected["settings"] = settings
	nodes, err := remote.InboundNodes(selected, serverRecord)
	if err != nil || len(nodes) != 1 {
		return nil, errors.New("用户已创建，唯一节点导入待重试")
	}
	result, err := c.Repository.ImportOwnedNode(profile, text(binding["operationId"]), nodes[0])
	if err != nil {
		return nil, err
	}
	result["shareLinks"] = []any{}
	if uri, e := links.Export(nodes[0]); e == nil {
		result["shareLinks"] = []any{uri}
	}
	if verified, present := response["runtimeVerified"]; present {
		result["runtimeVerified"] = verified
		result["runtimeRepaired"] = response["runtimeRepaired"]
		if verified == nil {
			result["warning"] = "当前内核不支持运行用户核验，请测试客户端连接"
		} else if response["runtimeRepaired"] == true {
			result["warning"] = "已补同步到运行内核"
		}
	}
	return result, nil
}

func (c *Controller) Info(profile string) (Record, error) {
	p, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	info, err := config.TrafficInfo(p, c.Now())
	if err != nil {
		return nil, err
	}
	plans, err := c.Repository.Plans()
	if err != nil {
		return nil, err
	}
	info["plans"] = plans
	return info, nil
}
