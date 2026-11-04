package remote

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

var errCoreStats = errors.New("独立内核统计接口或用户计数无法核对")

// Only the legacy managed loopback API may be queried. The executable is
// fixed, and its address must agree with the server's current config.
func coreStatsAddress(kind string, doc, saved Record) (string, error) {
	api := doc["api"]
	if kind == "sing-box" {
		experimental, _ := doc["experimental"].(Record)
		api = experimental["v2ray_api"]
	}
	settings, _ := api.(Record)
	listen := value(saved["listen"])
	address, err := netip.ParseAddrPort(listen)
	if err != nil || !address.Addr().IsLoopback() || address.Port() == 0 ||
		value(settings["listen"]) != listen || value(saved["binary"]) != "/usr/local/bin/xray" {
		return "", errCoreStats
	}
	if kind == "xray" {
		services, _ := settings["services"].([]any)
		for _, service := range services {
			if service == "StatsService" && settings["tag"] == "mxioc-user-stats" {
				if _, ok := doc["stats"].(Record); ok {
					return listen, nil
				}
			}
		}
	} else if stats, ok := settings["stats"].(Record); ok && stats["enabled"] == true {
		return listen, nil
	}
	return "", errCoreStats
}

type coreTraffic struct{ up, down int64 }

func parseCoreCounters(raw string) (map[string]coreTraffic, error) {
	var doc map[string]json.RawMessage
	if json.Unmarshal([]byte(raw), &doc) != nil || doc == nil {
		return nil, errCoreStats
	}
	var entries []struct {
		Name  string          `json:"name"`
		Value json.RawMessage `json:"value"`
	}
	if stats, exists := doc["stat"]; exists {
		if json.Unmarshal(stats, &entries) != nil || entries == nil {
			return nil, errCoreStats
		}
	} else if len(doc) != 0 {
		return nil, errCoreStats
	}
	result, seen := map[string]coreTraffic{}, map[string]bool{}
	for _, entry := range entries {
		parts := strings.Split(entry.Name, ">>>")
		if len(parts) != 4 || parts[0] != "user" || parts[1] == "" || parts[2] != "traffic" ||
			(parts[3] != "uplink" && parts[3] != "downlink") || seen[entry.Name] {
			return nil, errCoreStats
		}
		seen[entry.Name] = true
		raw := string(entry.Value)
		if raw == "" {
			raw = "0" // protobuf JSON omits default scalar values.
		} else if strings.HasPrefix(raw, "\"") && json.Unmarshal(entry.Value, &raw) != nil {
			return nil, errCoreStats
		}
		n, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || n < 0 {
			return nil, errCoreStats
		}
		counters := result[parts[1]]
		if parts[3] == "uplink" {
			counters.up = n
		} else {
			counters.down = n
		}
		result[parts[1]] = counters
	}
	return result, nil
}

type coreCounterUsers struct {
	count  int
	emails []string
}

func coreCounterIndex(kind string, doc, stats Record) (map[string]coreCounterUsers, map[string]int) {
	enabled := map[string]bool{}
	for _, email := range anyStrings(stats["users"]) {
		enabled[email] = true
	}
	if kind == "sing-box" {
		exp, _ := doc["experimental"].(Record)
		api, _ := exp["v2ray_api"].(Record)
		config, _ := api["stats"].(Record)
		actual := map[string]bool{}
		for _, email := range anyStrings(config["users"]) {
			actual[email] = enabled[email]
		}
		enabled = actual
	}

	byTag, counts := map[string]coreCounterUsers{}, map[string]int{}
	for _, native := range anyRecords(doc["inbounds"]) {
		var entries []Record
		field := "name"
		if kind == "sing-box" {
			entries = anyRecords(native["users"])
		} else {
			field = "email"
			settings, _ := native["settings"].(Record)
			entries = append(anyRecords(settings["clients"]), anyRecords(settings["users"])...)
			entries = append(entries, anyRecords(settings["accounts"])...)
		}
		group := coreCounterUsers{count: len(entries)}
		for _, client := range entries {
			email := value(client[field])
			counts[email]++
			if !enabled[email] || email == "" || strings.Contains(email, ">>>") {
				continue
			}
			if kind == "xray" {
				level := value(client["level"])
				if level == "" && client["level"] == nil {
					level = "0"
				}
				policy, _ := doc["policy"].(Record)
				levels, _ := policy["levels"].(Record)
				flags, _ := levels[level].(Record)
				if flags["statsUserUplink"] != true || flags["statsUserDownlink"] != true {
					continue
				}
			}
			group.emails = append(group.emails, email)
		}
		byTag[value(native["tag"])] = group
	}
	return byTag, counts
}

func applyCoreCounters(kind string, doc, stats, inventory Record, counters map[string]coreTraffic) {
	byTag, counts := coreCounterIndex(kind, doc, stats)
	for _, row := range anyRecords(inventory["inbounds"]) {
		if row["coreStatus"] != "present" {
			continue
		}
		group := byTag["mxioc-inbound-"+value(row["id"])]
		if group.count == 0 || len(group.emails) != group.count {
			continue
		}
		var totals coreTraffic
		valid := true
		for _, email := range group.emails {
			count := counters[email]
			if counts[email] != 1 || count.up > math.MaxInt64-totals.up || count.down > math.MaxInt64-totals.down {
				valid = false
				break
			}
			totals.up += count.up
			totals.down += count.down
		}
		if valid {
			row["up"], row["down"] = totals.up, totals.down
		}
	}
}

func queryCoreCounters(ctx context.Context, kind string, doc, stats Record, run coreRunner) (map[string]coreTraffic, error) {
	address, err := coreStatsAddress(kind, doc, stats)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	raw, err := run(ctx, "/usr/local/bin/xray api statsquery --server="+quote(address)+" --pattern='user>>>'", 2<<20)
	if err != nil {
		return nil, errCoreStats
	}
	return parseCoreCounters(raw)
}

func readCoreCounters(ctx context.Context, kind string, doc, stats, inventory Record, run coreRunner) error {
	counters, err := queryCoreCounters(ctx, kind, doc, stats, run)
	if err == nil {
		applyCoreCounters(kind, doc, stats, inventory, counters)
	}
	return err
}
