package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

// Legacy metadata supplies stable subscription IDs. Native configuration
// is compared with the reconstructed legacy config, including enabled users.
func coreInventory(kind string, record, doc Record, saved string) (Record, error) {
	native := map[string]Record{}
	if input, exists := doc["inbounds"]; exists {
		items, ok := input.([]any)
		if !ok {
			return nil, errors.New("独立内核入站列表无效")
		}
		for _, item := range items {
			row, ok := item.(map[string]any)
			if !ok {
				return nil, errors.New("独立内核入站格式无效")
			}
			tag := value(row["tag"])
			if tag == "" {
				continue
			}
			if native[tag] != nil {
				return nil, errors.New("独立内核存在重复入站标签")
			}
			native[tag] = row
		}
	}

	state, err := parseLegacyCoreState(saved)
	if err != nil {
		return nil, err
	}
	protocolKey, portKey := "protocol", "port"
	if kind == "sing-box" {
		protocolKey, portKey = "type", "listen_port"
	}
	rows := []any{}
	seen := map[int]bool{}
	for _, row := range state.Inbounds {
		id, err := strconv.Atoi(value(row["id"]))
		port, portErr := strconv.Atoi(value(row["port"]))
		protocol, tag := value(row["protocol"]), value(row["tag"])
		if err != nil || id < 1 || id > 2147483647 || seen[id] ||
			portErr != nil || port < 1 || port > 65535 || protocol == "" ||
			tag != "mxioc-inbound-"+strconv.Itoa(id) {
			return nil, errors.New("旧版独立内核托管入站身份无效或重复")
		}
		seen[id] = true
		actual := native[tag]
		status := "missing"
		switch {
		case actual == nil && row["enable"] == false:
			status = "disabled"
		case actual != nil && row["enable"] != false &&
			value(actual[protocolKey]) == protocol && value(actual[portKey]) == strconv.Itoa(port):
			status = "unverified"
			if expected, err := legacyNativeInbound(kind, row); err == nil {
				status = "mismatch"
				if sameCoreInbound(expected, actual) {
					status = "present"
				}
			}
		case actual != nil:
			status = "mismatch"
		}
		shares := []any{}
		if status == "present" {
			nodes, err := InboundNodes(row, record)
			if err == nil {
				for _, node := range nodes {
					if uri, err := links.Export(node); err == nil {
						shares = append(shares, uri)
					}
				}
			}
		}
		rows = append(rows, Record{
			"id": id, "port": port, "protocol": protocol, "remark": value(row["remark"]),
			"enable": status == "present" || status == "unverified", "coreStatus": status, "shareLinks": shares,
		})
	}
	return Record{"server": publicServer(record), "inbounds": rows, "readOnly": true, "coreStatsConfig": state.UserStats}, nil
}

func (m *Manager) standaloneInbounds(ctx context.Context, id string, withStats bool) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		raw, doc, err := readCore(ctx, kind, run)
		if err != nil {
			return nil, err
		}
		var saved string
		if record["coreState"] != nil {
			saved, err = m.Secret(record, "coreState")
			if err != nil {
				return nil, err
			}
		}
		inventory, err := coreInventory(kind, record, doc, saved)
		if err != nil {
			return nil, err
		}
		stats, _ := inventory["coreStatsConfig"].(Record)
		delete(inventory, "coreStatsConfig")
		var retryID string
		var statsPending bool
		if token := value(record["coreUserPending"]); token != "" {
			pending, err := m.OpenUser(token)
			hash := coreConfigHash(raw)
			statsPending = err == nil && pending["operation"] == coreStatsInit && (pending["before"] == hash || pending["after"] == hash)
			if err == nil && pending["operation"] == "add" && (pending["before"] == hash || pending["after"] == hash) {
				retryID = value(pending["inboundId"])
			}
		}
		state, err := parseLegacyCoreState(saved)
		if err != nil {
			return nil, err
		}
		byID := map[string]Record{}
		for _, row := range state.Inbounds {
			byID[value(row["id"])] = row
		}
		canInitialize := statsPending
		if len(stats) == 0 && value(record["coreUserPending"]) == "" {
			_, planErr := planCoreStats(kind, doc)
			canInitialize = planErr == nil
		}
		provision := []any{}
		for _, row := range anyRecords(inventory["inbounds"]) {
			id := value(row["id"])
			available := (row["coreStatus"] == "present" || id == retryID) && coreCanProvision(kind, doc, stats, value(row["protocol"]))
			needsStats := len(stats) == 0 && canInitialize && row["coreStatus"] == "present" &&
				coreProvisionProtocol(kind, value(row["protocol"]))
			row["provisionable"] = available || needsStats
			row["needsCoreStats"] = needsStats
			if withStats && len(stats) == 0 && row["coreStatus"] == "present" && value(record["coreUserPending"]) == "" {
				inventory["canEnableCoreStats"] = true
			}
			if (available || needsStats) && !withStats {
				provision = append(provision, byID[id])
			}
		}
		if withStats && statsPending {
			inventory["canEnableCoreStats"] = true
		}
		if !withStats {
			inventory["provisionInbounds"] = provision
		}
		if withStats && len(stats) != 0 {
			if err := readCoreCounters(ctx, kind, doc, stats, inventory, run); err != nil {
				inventory["coreStatsError"] = err.Error()
			}
		}
		return inventory, nil
	})
}

type legacyCoreState struct {
	Inbounds  []Record
	UserStats Record
}

func parseLegacyCoreState(saved string) (legacyCoreState, error) {
	var state legacyCoreState
	if saved == "" {
		return state, nil
	}
	decoder := json.NewDecoder(strings.NewReader(saved))
	decoder.UseNumber()
	if err := decoder.Decode(&state); err != nil || state.Inbounds == nil || !json.Valid([]byte(saved)) {
		return state, errors.New("旧版独立内核托管记录无效")
	}
	return state, nil
}

func sameCoreInbound(expected, actual Record) bool {
	want, wantErr := canonicalJSON(expected)
	got, gotErr := canonicalJSON(actual)
	return wantErr == nil && gotErr == nil && bytes.Equal(want, got)
}
