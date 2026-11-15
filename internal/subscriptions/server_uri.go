package subscriptions

import (
	"errors"
	"maps"
	"sort"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/managednodes"
)

func ServerURIFormat(format string) bool {
	return format == "v2rayn" || format == "v2rayng" || format == "v2ray" || format == "shadowrocket"
}

// Only explicit imported-node fingerprints establish ownership. Even inactive
// conflicting evidence prevents attributing a node to a different server.
func serverURIOwners(source config.Subscription) map[string]string {
	owners := map[string]string{}
	active := map[string]bool{}
	for _, binding := range objects(source.Managed["remoteNodes"]) {
		server := text(binding["serverId"])
		if server == "" {
			continue
		}
		for _, ref := range objects(binding["importedNodes"]) {
			identity := text(ref["identity"])
			if len(identity) != 64 {
				continue
			}
			if previous, exists := owners[identity]; exists && previous != server {
				owners[identity] = ""
			} else if !exists {
				owners[identity] = server
			}
			if binding["status"] == "active" {
				active[identity+"/"+server] = true
			}
		}
	}
	for identity, server := range owners {
		if server == "" || !active[identity+"/"+server] {
			delete(owners, identity)
		}
	}
	return owners
}
func ServerURIChoices(source config.Subscription) []Record {
	owners := serverURIOwners(source)
	counts := map[string]int{}
	for _, node := range objects(source.Document["proxies"]) {
		if id := owners[managednodes.Identity(node)]; id != "" {
			counts[id]++
		}
	}
	ids := []string{}
	for id := range counts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	result := []Record{}
	for _, id := range ids {
		result = append(result, Record{"id": id, "count": counts[id]})
	}
	return result
}
func FilterServerURI(source config.Subscription, server, format string) (config.Subscription, error) {
	if !ServerURIFormat(format) || server == "" || len(server) > 128 {
		return config.Subscription{}, errors.New("服务器筛选只支持 V2Ray / v2rayN / v2rayNG / Shadowrocket 节点订阅")
	}
	owners := serverURIOwners(source)
	nodes := []any{}
	for _, node := range objects(source.Document["proxies"]) {
		if owners[managednodes.Identity(node)] == server {
			nodes = append(nodes, node)
		}
	}
	if len(nodes) == 0 {
		return config.Subscription{}, errors.New("没有具有有效服务器归属的节点")
	}
	source.Document = maps.Clone(source.Document)
	source.Document["proxies"] = nodes
	return source, nil
}
