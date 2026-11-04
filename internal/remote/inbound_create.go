package remote

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (m *Manager) createJournal() (Record, error) {
	raw, err := os.ReadFile(filepath.Join(m.root, "inbound-creates.json"))
	if os.IsNotExist(err) {
		return Record{}, nil
	}
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	var data Record
	if decoder.Decode(&data) != nil || data == nil {
		return nil, errors.New("入站创建记录损坏，未下发新建请求")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return nil, errors.New("入站创建记录含多余内容")
	}
	for _, v := range data {
		entry, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("入站创建记录格式无效")
		}
		if entry["status"] == "canceled" && value(entry["scope"]) != "" {
			continue
		}
		for _, field := range []string{"serverId", "scope", "revision", "requestHash", "status", "sealedDesired"} {
			if _, ok := entry[field].(string); !ok || value(entry[field]) == "" {
				return nil, errors.New("入站创建记录字段无效")
			}
		}
		status := value(entry["status"])
		if status != "prepared" && status != "sent" && status != "confirmed" {
			return nil, errors.New("入站创建记录状态无效")
		}
	}
	return data, nil
}
func (m *Manager) saveCreate(key string, entry Record) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.createJournal()
	if err != nil {
		return err
	}
	if data[key] == nil && len(data) >= 4096 {
		return errors.New("入站创建历史已达上限，请先归档创建记录")
	}
	if previous, ok := data[key].(map[string]any); ok {
		if previous["status"] == "canceled" {
			return errors.New("此入站创建请求已取消")
		}
		for _, field := range []string{"serverId", "scope", "revision", "requestHash"} {
			if previous[field] != entry[field] {
				return errors.New("新建操作标识已被其他配置使用，未下发")
			}
		}
	}
	data[key] = entry
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return write(filepath.Join(m.root, "inbound-creates.json"), raw)
}
func (m *Manager) loadCreate(key string) (Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.createJournal()
	if err != nil {
		return nil, err
	}
	entry, _ := data[key].(map[string]any)
	return entry, nil
}

func (m *Manager) persistCreate(key string, current Record) error {
	desired, ok := current["desired"].(map[string]any)
	if !ok {
		return errors.New("新建入站配置无效")
	}
	sealed, err := m.SealUser(desired)
	if err != nil {
		return err
	}
	stored := Record{}
	for k, v := range current {
		if k != "desired" {
			stored[k] = v
		}
	}
	stored["sealedDesired"] = sealed
	return m.saveCreate(key, stored)
}
func createRequestIdentity(scope string, payload Record) (string, string, error) {
	operation := value(payload["operationId"])
	decoded, err := hex.DecodeString(operation)
	if err != nil || len(decoded) != 16 || len(operation) != 32 || scope == "" {
		return "", "", errors.New("缺少有效的新建操作标识，请重新打开创建窗口")
	}
	request := Record{}
	for k, v := range payload {
		if k != "operationId" && k != "serverId" {
			request[k] = v
		}
	}
	key, err := identity([]any{scope, operation})
	if err != nil {
		return "", "", err
	}
	hash, err := identity(request)
	return key, hash, err
}

func createServerRevision(record Record) string {
	revision, _ := identity([]any{certificateRevision(record), record["panelAddress"], record["panelUser"], record["panelPassword"], record["connectionMode"]})
	return revision
}

func creationRows(ctx context.Context, panel *Panel) ([]Record, error) {
	raw, err := panel.Request(ctx, "panel/api/inbounds/list", nil, "")
	if err != nil {
		return nil, err
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, errors.New("面板入站列表不完整，未创建节点")
	}
	ids := map[int]bool{}
	rows := []Record{}
	for _, v := range values {
		row, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("面板入站格式异常")
		}
		id, e := strconv.Atoi(value(row["id"]))
		port, e2 := parsedPort(row["port"], 0)
		if e != nil || id < 1 || ids[id] || e2 != nil || port < 1 {
			return nil, errors.New("面板入站 ID 或端口无效")
		}
		ids[id] = true
		rows = append(rows, row)
	}
	return rows, nil
}
func creationIdentity(row Record) (string, error) {
	data := Record{}
	for _, key := range inboundFields {
		if key != "up" && key != "down" {
			data[key] = row[key]
		}
	}
	return InboundVersion(data)
}
func confirmCreation(rows []Record, desired, entry Record) (Record, error) {
	if value(entry["status"]) == "confirmed" {
		for _, row := range rows {
			if value(row["id"]) == value(entry["inboundId"]) {
				hash, err := EndpointIdentity(row)
				if err != nil || hash != entry["endpointHash"] {
					return nil, errors.New("已创建入站身份已变化，未重复创建")
				}
				return row, nil
			}
		}
		return nil, errors.New("此操作创建的入站已被删除，未重新创建；请重新打开窗口")
	}
	want, err := creationIdentity(desired)
	if err != nil {
		return nil, err
	}
	var found Record
	for _, row := range rows {
		if value(row["port"]) != value(desired["port"]) {
			continue
		}
		got, err := creationIdentity(row)
		if err != nil || got != want {
			return nil, errors.New("目标端口出现不同配置，创建结果待核对；未重复下发")
		}
		if found != nil {
			return nil, errors.New("目标端口存在多条入站，创建结果待核对")
		}
		found = row
	}
	return found, nil
}

// A sent record is never sent again: retries only reconcile an authoritative
// list. The encrypted desired configuration survives disconnects and restarts.
func createPanelInbound(ctx context.Context, panel *Panel, record, payload, entry Record, persist func(Record) error) (Record, error) {
	desired, ok := entry["desired"].(map[string]any)
	if !ok {
		return nil, errors.New("入站创建配置缺失")
	}
	rows, err := creationRows(ctx, panel)
	if err != nil {
		return nil, err
	}
	status := value(entry["status"])
	if status == "confirmed" || status == "sent" {
		row, err := confirmCreation(rows, desired, entry)
		if err != nil {
			return nil, err
		}
		if row == nil {
			return nil, errors.New("创建结果待核对，远端暂未找到匹配入站；未重复下发，请刷新服务器列表")
		}
		if status != "confirmed" {
			hash, err := EndpointIdentity(row)
			if err != nil {
				return nil, err
			}
			entry["status"] = "confirmed"
			entry["inboundId"] = row["id"]
			entry["endpointHash"] = hash
			if err = persist(entry); err != nil {
				return nil, err
			}
		}
		return Record{"inbound": row, "reused": true}, nil
	}
	if status != "prepared" {
		return nil, errors.New("入站创建状态无效")
	}
	used := map[int]bool{}
	for _, row := range rows {
		port, _ := parsedPort(row["port"], 0)
		used[port] = true
	}
	port, _ := parsedPort(desired["port"], 0)
	if used[port] {
		if payload["port"] != nil && payload["port"] != "" {
			return nil, errors.New("监听端口已存在，请使用其他端口并重新打开创建窗口")
		}
		for attempt := 0; attempt < 128 && used[port]; attempt++ {
			port, err = randomInboundPort()
			if err != nil {
				return nil, err
			}
		}
		if used[port] {
			return nil, errors.New("未找到空闲随机端口，尚未创建节点")
		}
		desired["port"] = port
	}
	if err = validateTemplateCertificate(ctx, panel, payload); err != nil {
		return nil, err
	}
	body, _, err := prepareInboundEdit(desired, Record{})
	if err != nil {
		return nil, err
	}
	entry["status"] = "sent"
	if err = persist(entry); err != nil {
		return nil, err
	}
	if _, err = panel.RequestOnce(ctx, "panel/api/inbounds/add", body); err != nil {
		return nil, errors.New("新建请求结果待核对；请使用同一窗口重试核对，勿重复新建")
	}
	rows, err = creationRows(ctx, panel)
	if err != nil {
		return nil, errors.New("新建请求已下发，读取结果待核对；请在同一窗口重试")
	}
	row, err := confirmCreation(rows, desired, entry)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, errors.New("面板尚未返回匹配入站，结果待核对；请在同一窗口重试")
	}
	hash, err := EndpointIdentity(row)
	if err != nil {
		return nil, err
	}
	entry["status"] = "confirmed"
	entry["inboundId"] = row["id"]
	entry["endpointHash"] = hash
	if err = persist(entry); err != nil {
		return nil, errors.New("入站已创建，完成标记保存失败；请在同一窗口重试核对")
	}
	return Record{"inbound": row, "reused": false}, nil
}

func (m *Manager) CreateInbound(ctx context.Context, server, scope string, payload Record) (Record, error) {
	key, requestHash, err := createRequestIdentity(scope, payload)
	if err != nil {
		return nil, err
	}
	record, err := m.Record(server)
	if err != nil {
		return nil, err
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		return m.createStandaloneInbound(ctx, server, key, requestHash, payload, nil)
	}
	if templateName(payload) == "tuic" {
		return nil, errors.New("TUIC 模板需要独立 sing-box")
	}
	if grpcTemplate(templateName(payload)) {
		return nil, errors.New("当前 gRPC 模板需要独立 Xray 或 sing-box")
	}
	revision := createServerRevision(record)
	entry, err := m.loadCreate(key)
	if err != nil {
		return nil, err
	}
	prepared := payload
	if entry != nil {
		if entry["status"] == "canceled" {
			return nil, errors.New("此入站创建请求已取消")
		}
		if entry["serverId"] != server || entry["scope"] != scope || entry["revision"] != revision || entry["requestHash"] != requestHash {
			return nil, errors.New("创建配置或服务器身份已变化，请先核对之前的创建结果")
		}
		desired, e := m.OpenUser(value(entry["sealedDesired"]))
		if e != nil {
			return nil, e
		}
		entry["desired"] = desired
	} else {
		var address string
		prepared, address, err = m.templatePayload(server, record, payload)
		if err != nil {
			return nil, err
		}
		desired, e := buildInboundTemplate(prepared, address)
		if e != nil {
			return nil, e
		}
		entry = Record{"serverId": server, "scope": scope, "revision": revision, "requestHash": requestHash, "status": "prepared", "createdAt": time.Now().Unix(), "desired": desired}
	}
	persist := func(current Record) error { return m.persistCreate(key, current) }
	result, err := m.WithPanel(ctx, server, func(panel *Panel, latest Record) (any, error) {
		if createServerRevision(latest) != revision {
			return nil, errors.New("服务器身份已变化，尚未创建节点")
		}
		// Recheck after the per-server gate, including requests from another caller.
		previous, e := m.loadCreate(key)
		if e != nil {
			return nil, e
		}
		if previous != nil {
			if previous["status"] == "canceled" {
				return nil, errors.New("此入站创建请求已取消")
			}
			if previous["serverId"] != server || previous["scope"] != scope || previous["revision"] != revision || previous["requestHash"] != requestHash {
				return nil, errors.New("创建操作标识已用于其他配置")
			}
			desired, e := m.OpenUser(value(previous["sealedDesired"]))
			if e != nil {
				return nil, e
			}
			previous["desired"] = desired
			entry = previous
		} else if e = persist(entry); e != nil {
			return nil, e
		}
		if value(entry["status"]) == "prepared" && templateName(payload) == "vless-reality" {
			_, address, e := m.templatePayload(server, latest, payload)
			if e != nil {
				return nil, e
			}
			stream, e := inboundObject(entry["desired"].(Record)["streamSettings"])
			if e != nil {
				return nil, e
			}
			reality, e := inboundObject(stream["realitySettings"])
			if e != nil {
				return nil, e
			}
			if reality["target"] != net.JoinHostPort(address, "443") {
				return nil, errors.New("SNI 实测地址已变化，请先核对之前的创建记录")
			}
		}
		if value(entry["status"]) == "prepared" && tlsTemplate(templateName(payload)) {
			// Certificate jobs may have expired since the first request. The desired
			// configuration remains fixed; validation below uses its original paths.
			stream, _ := inboundObject(entry["desired"].(Record)["streamSettings"])
			tls, _ := inboundObject(stream["tlsSettings"])
			certs, _ := tls["certificates"].([]any)
			if len(certs) != 1 {
				return nil, errors.New("TLS 证书配置无效")
			}
			cert, _ := inboundObject(certs[0])
			copy := Record{}
			for k, v := range payload {
				copy[k] = v
			}
			copy["certFile"] = cert["certificateFile"]
			copy["keyFile"] = cert["keyFile"]
			copy["serverName"] = tls["serverName"]
			prepared = copy
		}
		return createPanelInbound(ctx, panel, latest, prepared, entry, persist)
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}
