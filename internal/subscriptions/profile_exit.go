package subscriptions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"sort"
	"strings"
)

type profileExitBackend interface {
	SetProfileExit(context.Context, string, string, []string, remote.Record) (remote.Record, error)
	CancelProfileExit(context.Context, string, string) error
}

func exitEmails(record Record, server string) ([]string, error) {
	seen := map[string]bool{}
	result := []string{}
	for _, b := range objects(record["remoteNodes"]) {
		if text(b["serverId"]) != server || b["status"] == "removed" {
			continue
		}
		if b["scope"] != "user" || b["dedicated"] == true {
			return nil, errors.New("专属出口仅支持有独立代理身份的用户绑定")
		}
		email := text(b["userEmail"])
		if !strings.HasPrefix(email, "mxioc-") {
			return nil, errors.New("套餐包含无法确认的代理用户身份")
		}
		if !seen[email] {
			seen[email] = true
			result = append(result, email)
		}
	}
	sort.Strings(result)
	return result, nil
}
func exitPolicy(p Record) Record { policy, _ := p["userExit"].(Record); return policy }
func (c *Controller) SetUserExit(ctx context.Context, profile, owner, label string, node Record, resume bool) (Record, error) {
	backend, ok := c.Backend.(profileExitBackend)
	if !ok {
		return nil, errors.New("服务器未支持用户出口")
	}
	initial, e := c.Repository.State(profile)
	if e != nil {
		return nil, e
	}
	ids := map[string]bool{}
	for _, b := range objects(initial["remoteNodes"]) {
		if b["status"] != "removed" {
			ids[text(b["serverId"])] = true
		}
	}
	for _, id := range objects(exitPolicy(initial)["servers"]) {
		ids[text(id["id"])] = true
	}
	keys := []string{}
	for id := range ids {
		if id == "" {
			return nil, errors.New("绑定服务器标识无效")
		}
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		unlock, e := c.lockServer(ctx, id)
		if e != nil {
			return nil, e
		}
		defer unlock()
	}
	unlock, e := c.lock(ctx, profile)
	if e != nil {
		return nil, e
	}
	defer unlock()
	current, e := c.Repository.State(profile)
	if e != nil {
		return nil, e
	}
	if text(current["packageOwner"]) != "" && current["packageOwner"] != owner {
		return nil, errors.New("套餐归属已变化")
	}
	for _, b := range objects(current["remoteNodes"]) {
		if b["status"] != "removed" && !ids[text(b["serverId"])] {
			return nil, errors.New("套餐服务器已变化，请重试")
		}
	}
	policy := exitPolicy(current)
	if resume {
		if policy == nil || policy["status"] != "pending" {
			return nil, errors.New("没有待恢复的出口操作")
		}
		label = text(policy["label"])
		node = nil
		if token := text(policy["sealedNode"]); token != "" {
			node, e = c.Backend.OpenUser(token)
			if e != nil {
				return nil, e
			}
		}
	}
	raw, _ := json.Marshal(node)
	digest := sha256.Sum256(raw)
	hash := hex.EncodeToString(digest[:])
	clearingPending := policy != nil && policy["status"] == "pending" && node == nil && !resume
	if clearingPending {
		for _, id := range keys {
			if e := backend.CancelProfileExit(ctx, id, profile); e != nil {
				return nil, e
			}
		}
	}
	if policy != nil && policy["status"] == "pending" && policy["hash"] != hash && !clearingPending {
		return nil, errors.New("上次出口变更尚未完成，请先继续核对原请求")
	}
	if node != nil {
		if len(keys) == 0 {
			return nil, errors.New("请先为套餐添加独立托管用户")
		}
		if node["dialer-proxy"] != nil {
			return nil, errors.New("出口请选择普通节点")
		}
		if _, e = remote.NodeOutbound(node, "preflight"); e != nil {
			return nil, e
		}
	}
	for _, id := range keys {
		r, e := c.Backend.Record(id)
		if e != nil {
			return nil, e
		}
		if r["installType"] != "xray" {
			return nil, errors.New("此套餐包含非独立 Xray 服务器，未开始修改")
		}
		if node != nil {
			host := chainHost(text(node["server"]))
			same := false
			for _, key := range []string{"host", "domain", "nodeAddress"} {
				if host != "" && host == chainHost(text(r[key])) {
					same = true
				}
			}
			if same {
				for _, b := range objects(current["remoteNodes"]) {
					if b["serverId"] == id && text(b["port"]) == text(node["port"]) {
						return nil, errors.New("出口指向此套餐自身的入口端口，会形成循环，未开始修改")
					}
				}
			}
		}

		if _, e = exitEmails(current, id); e != nil {
			return nil, e
		}
	}
	if policy == nil || policy["status"] != "pending" || clearingPending {
		sealed := ""
		if node != nil {
			sealed, e = c.Backend.SealUser(node)
			if e != nil {
				return nil, e
			}
		}
		servers := []any{}
		for _, id := range keys {
			servers = append(servers, Record{"id": id, "status": "pending"})
		}
		policy = Record{"status": "pending", "hash": hash, "sealedNode": sealed, "label": label, "servers": servers, "updatedAt": c.Now().Unix()}
		if e = c.Repository.UpdateState(profile, func(p Record) error { p["packageOwner"] = owner; p["userExit"] = policy; return nil }); e != nil {
			return nil, e
		}
	}
	for _, id := range keys {
		emails, e := exitEmails(current, id)
		if e != nil {
			return nil, e
		}
		// Clear even when the last binding was removed, using retained server IDs.
		if _, e = backend.SetProfileExit(ctx, id, profile, emails, node); e != nil {
			c.Repository.UpdateState(profile, func(p Record) error {
				exitPolicy(p)["error"] = "服务器出口应用未完成，请继续核对"
				return nil
			})
			return nil, errors.New("套餐出口部分应用待核对；订阅凭据未改变，请重试原操作：" + e.Error())
		}
		if e = c.Repository.UpdateState(profile, func(p Record) error {
			for _, r := range objects(exitPolicy(p)["servers"]) {
				if r["id"] == id {
					r["status"] = "applied"
				}
			}
			return nil
		}); e != nil {
			return nil, e
		}
	}
	e = c.Repository.UpdateState(profile, func(p Record) error {
		if node == nil {
			delete(p, "userExit")
			delete(p, "packageOwner")
		} else {
			exitPolicy(p)["status"] = "active"
			delete(exitPolicy(p), "error")
		}
		return nil
	})
	return Record{"enabled": node != nil, "servers": len(keys)}, e
}

// Called before granting a new user. The route must exist before credentials
// become usable, including a newly added server in an existing package.
func (c *Controller) ensureUserExit(ctx context.Context, profile, server string) error {
	p, e := c.Repository.State(profile)
	if e != nil {
		return e
	}
	policy := exitPolicy(p)
	if policy == nil {
		return nil
	}
	if policy["status"] != "active" {
		return errors.New("套餐出口变更未完成，暂停新增用户")
	}
	node, e := c.Backend.OpenUser(text(policy["sealedNode"]))
	if e != nil {
		return e
	}
	backend, ok := c.Backend.(profileExitBackend)
	if !ok {
		return errors.New("出口接口不可用")
	}
	row, e := c.Backend.Record(server)
	if e != nil {
		return e
	}
	if row["installType"] != "xray" {
		return errors.New("此套餐出口不支持当前服务器内核")
	}
	emails, e := exitEmails(p, server)
	if e != nil {
		return e
	}
	if _, e = backend.SetProfileExit(ctx, server, profile, emails, node); e != nil {
		saveErr := c.Repository.UpdateState(profile, func(p Record) error {
			policy := exitPolicy(p)
			if policy == nil {
				return errors.New("套餐出口记录缺失")
			}
			policy["status"] = "pending"
			policy["error"] = "新节点的出口路由待核对；请在用户套餐中继续核对后重试创建"
			return nil
		})
		return errors.Join(e, saveErr)
	}
	return c.Repository.UpdateState(profile, func(p Record) error {
		policy := exitPolicy(p)
		for _, r := range objects(policy["servers"]) {
			if r["id"] == server {
				return nil
			}
		}
		policy["servers"] = append(objectsAsAny(objects(policy["servers"])), Record{"id": server, "status": "applied"})
		return nil
	})
}
func objectsAsAny(rows []Record) []any {
	out := make([]any, len(rows))
	for i, r := range rows {
		out[i] = r
	}
	return out
}

// ResetPackageUsage settles the currently measured deltas first, then resets
// only this subscription's visible counters; remote absolute baselines remain.
func (c *Controller) ResetPackageUsage(ctx context.Context, profile string) (Record, error) {
	unlock, e := c.lock(ctx, profile)
	if e != nil {
		return nil, e
	}
	defer unlock()
	if _, e = c.syncLocked(ctx, profile, false); e != nil {
		return nil, e
	}
	e = c.Repository.UpdateState(profile, func(p Record) error {
		if text(p["enforcementError"]) != "" {
			return errors.New("流量结算未完成，未重置")
		}
		t := traffic(p)
		if t["enabled"] != true {
			return errors.New("套餐流量尚未启用")
		}
		for _, key := range []string{"upload", "download", "rawUpload", "rawDownload"} {
			t[key] = int64(0)
		}
		t["updatedAt"] = c.Now().Unix()
		t["manualResetAt"] = c.Now().Unix()
		for _, b := range objects(p["remoteNodes"]) {
			b["uploadRemainder"] = int64(0)
			b["downloadRemainder"] = int64(0)
		}
		return nil
	})
	if e != nil {
		return nil, e
	}
	c.wakeEnforcement()
	return c.Info(profile)
}
