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

	var state struct {
		Inbounds []Record
	}
	if saved != "" {
		decoder := json.NewDecoder(strings.NewReader(saved))
		decoder.UseNumber()
		if err := decoder.Decode(&state); err != nil || state.Inbounds == nil || !json.Valid([]byte(saved)) {
			return nil, errors.New("旧版独立内核托管记录无效")
		}
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
				want, wantErr := canonicalJSON(expected)
				got, gotErr := canonicalJSON(actual)
				if wantErr == nil && gotErr == nil && bytes.Equal(want, got) {
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
	return Record{"server": publicServer(record), "inbounds": rows, "readOnly": true}, nil
}

func (m *Manager) standaloneInbounds(ctx context.Context, id string) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		_, doc, err := readCore(ctx, kind, run)
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
		return coreInventory(kind, record, doc, saved)
	})
}
