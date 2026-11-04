package subscriptions

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"github.com/Angasky/dingzhi-ban/internal/managednodes"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type chainServerRegistry interface {
	List() ([]remote.Record, error)
}

func chainHost(value string) string {
	value = strings.Trim(strings.TrimSpace(value), "[]")
	if address, err := netip.ParseAddr(value); err == nil {
		return address.Unmap().String()
	}
	return strings.ToLower(strings.TrimSuffix(value, "."))
}

func matchChainServer(servers []Record, node Record) (Record, error) {
	host := chainHost(text(node["server"]))
	var found Record
	for _, server := range servers {
		for _, key := range []string{"host", "domain", "nodeAddress"} {
			if host == "" || host != chainHost(text(server[key])) {
				continue
			}
			if found != nil {
				return nil, errors.New("节点地址匹配到多台服务器")
			}
			found = server
			break
		}
	}
	if found == nil {
		return nil, errors.New("节点地址没有匹配到已登记服务器")
	}
	return found, nil
}

func matchChainInbound(snapshot, node Record) (string, error) {
	rows, _, err := inventoryRows(snapshot)
	if err != nil {
		return "", err
	}
	var matched string
	for _, row := range rows {
		if row["enable"] == false || text(row["port"]) != text(node["port"]) {
			continue
		}
		uris, _ := row["shareLinks"].([]any)
		for _, uri := range uris {
			candidate, err := links.Parse(text(uri))
			if err != nil {
				continue
			}
			candidate["server"] = node["server"]
			if managednodes.Identity(candidate) != managednodes.Identity(node) {
				continue
			}
			if matched != "" {
				return "", errors.New("节点凭据匹配到多个远端用户")
			}
			matched = text(uri)
		}
	}
	if matched == "" {
		return "", errors.New("节点未匹配到服务器上的启用入站及用户")
	}
	return matched, nil
}

func (c *Controller) CreateServerChain(ctx context.Context, profile string, input Record) (Record, error) {
	registry, ok := c.Backend.(chainServerRegistry)
	if !ok {
		return nil, errors.New("服务器链路创建尚未适配")
	}
	chain := &config.ServerChainImport{
		Name: strings.TrimSpace(text(input["name"])), Entry: text(input["entry"]), Exit: text(input["exit"]),
		Request: text(input["operationId"]), Groups: input["groups"],
	}
	if chain.Groups == nil {
		chain.Groups = []any{}
	}
	entry, exit, err := c.Repository.ServerChainSources(profile, chain)
	if err != nil {
		return nil, err
	}
	servers, err := registry.List()
	if err != nil {
		return nil, err
	}
	ingress, err := matchChainServer(servers, entry)
	if err != nil {
		return nil, err
	}
	egress, err := matchChainServer(servers, exit)
	if err != nil {
		return nil, err
	}
	if ingress["id"] == egress["id"] {
		return nil, errors.New("入口与出口需要选择不同的服务器")
	}
	template := "vless-reality"
	switch ingress["installType"] {
	case "3x-ui", "x-ui", "x-panel", "xray":
	case "sing-box":
		template = "vmess-tcp"
	default:
		return nil, errors.New("服务器中转入口需要已接入的 Web 面板或独立内核")
	}
	payload := Record{"operationId": chain.Request, "remark": chain.Name, "template": template,
		"port": input["port"], "serverName": input["serverName"], "sniVerified": input["sniVerified"],
		"sniAddress": input["sniAddress"], "chainEntry": chain.Entry, "chainExit": chain.Exit, "chainGroups": chain.Groups}
	prepare := func() error {
		currentEntry, currentExit, err := c.Repository.ServerChainSources(profile, chain)
		if err != nil {
			return err
		}
		if !reflect.DeepEqual(entry, currentEntry) || !reflect.DeepEqual(exit, currentExit) {
			return errors.New("入口或出口节点已变化，请重新打开创建窗口")
		}
		entryRows, err := c.Backend.Inbounds(ctx, text(ingress["id"]))
		if err != nil {
			return err
		}
		if _, err = matchChainInbound(entryRows, entry); err != nil {
			return err
		}
		exitRows, err := c.Backend.Inbounds(ctx, text(egress["id"]))
		if err != nil {
			return err
		}
		payload["landingLink"], err = matchChainInbound(exitRows, exit)
		return err
	}
	return c.createInbound(ctx, profile, text(ingress["id"]), payload, true, chain, prepare)
}
