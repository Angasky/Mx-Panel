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
				if sameCoreInbound(expected, actual) && verifyCoreRelay(doc, row) == nil {
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
		entry := Record{
			"id": id, "port": port, "protocol": protocol, "remark": value(row["remark"]),
			"enable": status == "present" || status == "unverified", "coreStatus": status, "shareLinks": shares,
			"coreRelay": coreRelayProof(row) != nil,
		}
		if status == "missing" && value(record["coreUserPending"]) == "" {
			if hash, err := EndpointIdentity(row); err == nil {
				entry["missingUserIdentity"] = hash
			}
			if hash, err := LegacyInboundIdentity(row); err == nil {
				entry["missingLegacyIdentity"] = hash
			}
		}
		rows = append(rows, entry)
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
		var deleteRetryID, deleteRetryToken string
		var editPending, editRetry Record
		var statsPending bool
		if token := value(record["coreUserPending"]); token != "" {
			pending, err := m.OpenUser(token)
			hash := coreConfigHash(raw)
			statsPending = err == nil && pending["operation"] == coreStatsInit && (pending["before"] == hash || pending["after"] == hash)
			if err == nil && pending["operation"] == "add" && (pending["before"] == hash || pending["after"] == hash) {
				retryID = value(pending["inboundId"])
			}
			if err == nil && pending["operation"] == coreInboundDelete && (pending["before"] == hash || pending["after"] == hash) {
				deleteRetryID, deleteRetryToken = value(pending["inboundId"]), value(pending["key"])
			}
			if err == nil && pending["operation"] == coreInboundEdit {
				editPending = pending
				if pending["before"] == hash || pending["after"] == hash {
					editRetry = pending
				}
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
			if !withStats && coreRelayProof(byID[id]) != nil {
				if id == deleteRetryID {
					row["deleteToken"] = deleteRetryToken
				} else if row["coreStatus"] == "present" && value(record["coreUserPending"]) == "" {
					if version, err := InboundVersion(byID[id]); err == nil {
						row["deleteToken"] = version
					}
				}
			}
			if withStats {
				switch {
				case id == deleteRetryID:
					row["deleteToken"] = deleteRetryToken
					row["deletePending"] = true
				case id == value(editPending["inboundId"]):
					row["editPending"] = true
					if editRetry != nil {
						row["editToken"], row["editFields"], row["editPatch"] = editRetry["key"], editRetry["fields"], editRetry["patch"]
					}
				case value(record["coreUserPending"]) == "" && (row["coreStatus"] == "present" || row["coreStatus"] == "disabled"):
					if version, err := InboundVersion(byID[id]); err == nil {
						row["editToken"], row["deleteToken"] = version, version
						row["editFields"] = managedCoreFields(byID[id])
					}
				}
			}
			supported := coreProvisionInbound(kind, byID[id])
			available := supported && (row["coreStatus"] == "present" || id == retryID) && coreCanProvision(kind, doc, stats, value(row["protocol"]))
			available = available && id != deleteRetryID && id != value(editPending["inboundId"])
			needsStats := supported && len(stats) == 0 && canInitialize && row["coreStatus"] == "present"
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
			dedicated := []any{}
			for _, row := range anyRecords(inventory["inbounds"]) {
				if row["coreStatus"] == "present" {
					if _, err := DedicatedPasswordBinding(byID[value(row["id"])], Record{}); err == nil {
						dedicated = append(dedicated, byID[value(row["id"])])
					}
				}
			}
			inventory["dedicatedInbounds"] = dedicated
		}
		if withStats && len(stats) != 0 {
			if err := readCoreCounters(ctx, kind, doc, stats, inventory, run); err != nil {
				inventory["coreStatsError"] = err.Error()
			}
		}
		if withStats && kind == "sing-box" {
			if config, ok := ctx.Value(singConfigKey{}).(*singConfig); ok {
				sources := map[string]string{}
				for _, file := range config.Files {
					for _, row := range anyRecords(file.Doc["inbounds"]) {
						sources[value(row["tag"])] = file.Path
					}
				}
				rows, _ := inventory["inbounds"].([]any)
				for _, native := range anyRecords(doc["inbounds"]) {
					tag := value(native["tag"])
					if tag == "" || strings.HasPrefix(tag, "mxioc-inbound-") {
						continue
					}
					protocol := value(native["type"])
					if protocol == "tun" || protocol == "direct" {
						continue
					}
					rows = append(rows, Record{"id": "native:" + tag, "nativeTag": tag, "remark": tag, "protocol": protocol, "port": native["listen_port"], "coreStatus": "native", "source": sources[tag], "enable": true, "provisionable": false, "shareLinks": []any{}})
				}
				inventory["inbounds"] = rows
				inventory["configFiles"] = len(config.Files)
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
