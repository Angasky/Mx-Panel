package remote

import (
	"context"
	"encoding/json"
	"errors"
	"maps"
	"strconv"
	"strings"
	"unicode"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

const coreInboundEdit = "core-inbound-edit"

// Expose connection fields without exposing the credentials or TLS keys.
func managedCoreFields(row Record) Record {
	fields := Record{"remark": value(row["remark"]), "port": row["port"]}
	stream, _ := object(row["streamSettings"])
	switch value(stream["network"]) {
	case "ws":
		ws, _ := object(stream["wsSettings"])
		path := value(ws["path"])
		if path == "" {
			path = "/"
		}
		fields["wsPath"] = path
	case "grpc":
		grpc, _ := object(stream["grpcSettings"])
		fields["grpcService"] = value(grpc["serviceName"])
	case "xhttp":
		if opts, err := links.XHTTPOptions(stream["xhttpSettings"]); err == nil {
			fields["xhttpPath"], fields["xhttpMode"] = opts["path"], opts["mode"]
		}
	}
	return fields
}

func prepareManagedCoreEdit(old, payload Record) (Record, error) {
	if len(payload) == 0 {
		return nil, errors.New("请填写要修改的托管入站配置")
	}
	next := maps.Clone(old)
	fields := managedCoreFields(old)
	for key, input := range payload {
		if _, ok := fields[key]; !ok {
			return nil, errors.New("当前入站不支持修改此字段")
		}
		if key == "port" {
			port, err := parsedPort(input, 0)
			if err != nil || port == 0 {
				return nil, errors.New("入站端口必须为 1–65535")
			}
			if value(port) != value(old["port"]) {
				next["port"] = port
			}
			continue
		}
		text, ok := input.(string)
		if !ok || strings.ContainsFunc(text, unicode.IsControl) {
			return nil, errors.New("入站名称或传输参数无效")
		}
		if key == "remark" {
			text = strings.TrimSpace(text)
			if text == "" || len([]rune(text)) > 100 {
				return nil, errors.New("请填写 1–100 字符的托管入站名称")
			}
			next["remark"] = text
			continue
		}
		if text == fields[key] {
			continue
		}
		if len(text) > 256 || strings.ContainsFunc(text, unicode.IsSpace) {
			return nil, errors.New("传输参数过长或包含空白字符")
		}
		group, field := "grpcSettings", "serviceName"
		if key == "wsPath" {
			if !strings.HasPrefix(text, "/") || strings.ContainsAny(text, "?#") {
				return nil, errors.New("WebSocket 路径必须以 / 开头，且不能包含查询或片段")
			}
			group, field = "wsSettings", "path"
		}
		switch key {
		case "xhttpPath":
			group, field = "xhttpSettings", "path"
		case "xhttpMode":
			group, field = "xhttpSettings", "mode"
		}
		stream, err := object(next["streamSettings"])
		if err != nil {
			return nil, err
		}
		options, err := object(stream[group])
		if err != nil {
			return nil, err
		}
		stream, options = maps.Clone(stream), maps.Clone(options)
		options[field] = text
		if group == "xhttpSettings" {
			if _, err := links.XHTTPOptions(options); err != nil {
				return nil, errors.New("XHTTP 路径或传输模式无效")
			}
		}
		stream[group] = options
		next["streamSettings"] = stream
	}
	return next, nil
}

func (m *Manager) editManagedCoreInbound(ctx context.Context, server, kind string, record, stateDoc Record, rows []Record, index int, status, expected string, payload Record, raw []byte, doc Record, guard func(Record, Record) error, run coreRunner) (Record, error) {
	stateToken, pending := value(record["coreState"]), value(record["coreUserPending"])
	old := rows[index]
	before := coreConfigHash(raw)
	journal, _, err := m.coreUserJournal(pending, expected, coreInboundEdit, before)
	if err != nil {
		return nil, err
	}
	if journal == nil && status != "present" && status != "disabled" {
		return nil, errors.New("托管入站配置尚未核对，暂不能修改")
	}
	nextRow, err := prepareManagedCoreEdit(old, payload)
	if err != nil {
		return nil, err
	}
	version, err := InboundVersion(nextRow)
	if err != nil {
		return nil, err
	}
	if journal != nil && journal["version"] != version {
		return nil, errors.New("请按上次提交的配置重试")
	}
	if err := guard(old, nextRow); err != nil {
		return nil, err
	}
	if version == expected {
		return Record{"updated": true}, nil
	}

	oldEndpoint, err := EndpointIdentity(old)
	if err != nil {
		return nil, err
	}
	nextEndpoint, err := EndpointIdentity(nextRow)
	if err != nil {
		return nil, err
	}
	remoteChange := oldEndpoint != nextEndpoint
	id, _ := strconv.Atoi(value(old["id"])) // The managed inventory already validated the ID.
	if remoteChange && dependentInbound(record, id) {
		return nil, errors.New("入站仍关联限速、计量或中转配置，请先清理关联资源")
	}
	tag := value(old["tag"])
	next := maps.Clone(doc)
	if remoteChange {
		if value(old["port"]) != value(nextRow["port"]) {
			port := value(nextRow["port"])
			for _, candidate := range anyRecords(doc["inbounds"]) {
				if candidate["tag"] != tag && (value(candidate["port"]) == port || value(candidate["listen_port"]) == port) {
					return nil, errors.New("监听端口已被远端入站使用")
				}
			}
		}
		if old["enable"] != false {
			native, err := legacyNativeInbound(kind, nextRow)
			if err != nil {
				return nil, err
			}
			live := []any{}
			for _, candidate := range anyRecords(doc["inbounds"]) {
				if candidate["tag"] == tag {
					candidate = native
				}
				live = append(live, candidate)
			}
			next["inbounds"] = live
		}
	}
	rows[index] = nextRow
	stateDoc["inbounds"] = rows
	nextState, err := m.SealUser(stateDoc)
	if err != nil {
		return nil, err
	}
	if remoteChange && old["enable"] != false {
		data, err := json.Marshal(next)
		if err != nil {
			return nil, err
		}
		after := coreConfigHash(data)
		if journal == nil {
			journal = Record{"key": expected, "operation": coreInboundEdit, "before": before, "after": after,
				"inboundId": value(old["id"]), "version": version, "fields": managedCoreFields(nextRow), "patch": payload}
			pending, err = m.SealUser(journal)
			if err != nil {
				return nil, err
			}
			if err := m.updateCoreUserState(server, stateToken, "", stateToken, pending); err != nil {
				return nil, err
			}
		} else if journal["after"] != after {
			return nil, errors.New("独立内核编辑计划与保存记录不一致")
		}
		if _, err := applyCore(ctx, kind, raw, next, tag, run); err != nil {
			if (errors.Is(err, errCoreRolledBack) || errors.Is(err, errCoreValidation)) && journal["before"] == before {
				err = errors.Join(err, m.updateCoreUserState(server, stateToken, pending, stateToken, ""))
			}
			return nil, err
		}
	}
	if err := m.updateCoreUserState(server, stateToken, pending, nextState, ""); err != nil {
		return nil, errors.New("托管入站保存待核对，请刷新列表重试")
	}
	return Record{"updated": true}, nil
}
