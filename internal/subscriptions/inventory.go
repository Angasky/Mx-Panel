package subscriptions

import (
	"context"
	"errors"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func inventoryRows(snapshot Record) ([]Record, map[int]bool, error) {
	values, ok := snapshot["inbounds"].([]any)
	if !ok {
		return nil, nil, errors.New("服务器入站列表不完整，未清理节点")
	}
	rows := []Record{}
	live := map[int]bool{}
	for _, v := range values {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, nil, errors.New("服务器入站格式异常")
		}
		id, err := number(row["id"], -1)
		if err != nil || id <= 0 || live[int(id)] {
			return nil, nil, errors.New("服务器入站 ID 无效或重复")
		}
		live[int(id)] = true
		rows = append(rows, row)
	}
	return rows, live, nil
}

func (c *Controller) ReconcileServer(ctx context.Context, server string, snapshot Record, observed map[string]bool) (Record, error) {
	_, live, err := inventoryRows(snapshot)
	if err != nil {
		return nil, err
	}
	profiles, err := c.Repository.ServerProfiles(server)
	if err != nil {
		return nil, err
	}
	removed := 0
	failures := []string{}
	for _, id := range profiles {
		release, err := c.lock(ctx, id)
		if err != nil {
			return nil, err
		}
		n, err := c.Repository.ReconcileInventory(id, server, live, observed)
		release()
		removed += n
		if err != nil {
			failures = append(failures, "订阅节点清理失败，已保留身份记录等待重试")
		}
	}
	return Record{"removed": removed, "errors": failures}, nil
}

// Called while the profile operation lock is held. A failed read never becomes
// an empty inventory. Availability reconciliation is independent of quota flags.
func (c *Controller) reconcileProfileLocked(ctx context.Context, profile string) []string {
	failures := []string{}
	if _, err := c.Repository.CleanupMissing(profile); err != nil {
		failures = append(failures, "订阅节点清理失败，等待重试")
	}
	p, err := c.Repository.State(profile)
	if err != nil {
		return append(failures, err.Error())
	}
	servers := map[string]bool{}
	for _, b := range objects(p["remoteNodes"]) {
		if b["status"] == "active" || b["status"] == "provisioning" {
			servers[text(b["serverId"])] = true
		}
	}
	for server := range servers {
		observed, err := c.Repository.BindingSnapshot(server)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		snapshot, err := c.Backend.Inbounds(ctx, server)
		if err != nil {
			failures = append(failures, "服务器不可达，已保留订阅节点")
			continue
		}
		rows, live, err := inventoryRows(snapshot)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if _, err = c.Repository.ReconcileInventory(profile, server, live, observed); err != nil {
			failures = append(failures, "缺失节点清理失败，等待重试")
			continue
		}
		byID := map[string]Record{}
		for _, row := range rows {
			byID[text(row["id"])] = row
		}
		current, err := c.Repository.State(profile)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		for _, b := range objects(current["remoteNodes"]) {
			if b["serverId"] != server || b["scope"] != "user" || b["status"] != "active" || !observed[config.BindingToken(profile, b)] {
				continue
			}
			row := byID[text(b["inboundId"])]
			if row == nil {
				continue
			}
			user, err := remote.FindUser(row, b, true)
			if err == nil && user == nil {
				if err = c.updateBinding(profile, b, func(_ Record, b Record) error {
					b["status"] = "missing"
					b["error"] = "远端订阅用户已不存在"
					return nil
				}); err != nil {
					failures = append(failures, err.Error())
					continue
				}
				if _, err = c.Repository.CleanupMissing(profile); err != nil {
					failures = append(failures, "缺失用户节点清理失败，等待重试")
				}
			}
		}
	}
	return failures
}
