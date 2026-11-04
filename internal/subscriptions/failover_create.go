package subscriptions

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

func (c *Controller) CreateFailover(ctx context.Context, profile string, input Record) (Record, error) {
	if profile == "" {
		profile = "clash"
	}
	release, err := c.lock(ctx, "failover:"+profile)
	if err != nil {
		return nil, err
	}
	defer release()
	entries, entriesOK := input["entries"].([]any)
	groups, groupsOK := input["groups"].([]any)
	name, exit, operation := strings.TrimSpace(text(input["name"])), text(input["exit"]), text(input["operationId"])
	interval, err := number(input["interval"], 30)
	decoded, decodeErr := hex.DecodeString(operation)
	if err != nil || decodeErr != nil || len(decoded) != 16 || len(operation) != 32 || !entriesOK ||
		len(entries) < 2 || len(entries) > 8 || !groupsOK || interval < 10 || interval > 600 ||
		name == "" || len([]rune(name)) > 92 || strings.ContainsAny(name, ",\r\n\x00") || exit == "" ||
		slices.Contains([]string{"DIRECT", "REJECT", "REJECT-DROP", "PASS"}, name) {
		return nil, errors.New("请填写主备名称、2–8 个入口、固定出口及 10–600 秒检测间隔")
	}
	var port any = ""
	if input["port"] != nil && input["port"] != "" {
		value, err := strconv.Atoi(text(input["port"]))
		if err != nil || value < 1 || value > 65535 {
			return nil, errors.New("监听端口无效")
		}
		port = value
	}
	plan := Record{"name": name, "entries": entries, "exit": exit, "groups": groups, "interval": int(interval),
		"port": port, "serverName": text(input["serverName"]), "operationId": operation,
		"requestId": operation, "status": "creating"}
	payload, err := json.Marshal(plan)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	plan["requestHash"] = hex.EncodeToString(digest[:])
	state, err := c.Repository.State(profile)
	if err != nil {
		return nil, err
	}
	for _, item := range objects(state["failovers"]) {
		if item["requestId"] == operation && item["requestHash"] == plan["requestHash"] && item["status"] == "active" {
			return item, nil
		}
	}
	registry, ok := c.Backend.(chainServerRegistry)
	if !ok {
		return nil, errors.New("服务器主备创建尚未适配")
	}
	servers, err := registry.List()
	if err != nil {
		return nil, err
	}
	seen, ingressIDs := map[string]bool{exit: true}, map[string]bool{}
	paths, pathRequests := []any{}, []any{}
	requests := []Record{}
	for i, value := range entries {
		entryName := text(value)
		if entryName == "" || seen[entryName] {
			return nil, errors.New("入口与出口不能重复")
		}
		seen[entryName] = true
		path := fmt.Sprintf("%s / %d", name, i+1)
		requestID := config.FailoverPathRequest(operation, i)
		request := Record{"name": path, "entry": entryName, "exit": exit, "operationId": requestID,
			"groups": []any{}, "port": plan["port"], "serverName": plan["serverName"]}
		entry, landing, err := c.Repository.ServerChainSources(profile, &config.ServerChainImport{
			Name: path, Entry: entryName, Exit: exit, Request: requestID, Groups: request["groups"],
		})
		if err != nil {
			return nil, err
		}
		ingress, err := matchChainServer(servers, entry)
		if err != nil {
			return nil, err
		}
		egress, err := matchChainServer(servers, landing)
		if err != nil {
			return nil, err
		}
		id := text(ingress["id"])
		if ingressIDs[id] || id == text(egress["id"]) {
			return nil, errors.New("所有入口与固定出口必须使用不同服务器")
		}
		ingressIDs[id] = true
		paths, pathRequests = append(paths, path), append(pathRequests, requestID)
		requests = append(requests, request)
	}
	plan["paths"], plan["pathRequests"] = paths, pathRequests
	if err := c.Repository.BeginFailover(profile, plan); err != nil {
		return nil, err
	}
	completed := map[string]bool{}
	for _, chain := range objects(state["serverChains"]) {
		completed[text(chain["requestId"])] = true
	}
	for _, request := range requests {
		if completed[text(request["operationId"])] {
			continue
		}
		if _, err := c.createServerChain(ctx, profile, request, true); err != nil {
			return nil, fmt.Errorf("主备路径 %s 尚未完成，可从列表继续创建：%w", request["name"], err)
		}
	}
	unlock, err := c.lock(ctx, profile)
	if err != nil {
		return nil, err
	}
	defer unlock()
	return c.Repository.ActivateFailover(profile, plan)
}
