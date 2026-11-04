package remote

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"strconv"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/legacycrypto"
)

func (m *Manager) SealUser(client Record) (string, error) {
	data, err := json.Marshal(client)
	if err != nil {
		return "", err
	}
	return legacycrypto.EncryptFernet(m.key, data)
}
func (m *Manager) OpenUser(token string) (Record, error) {
	data, err := legacycrypto.DecryptFernet(m.key, token)
	if err != nil {
		return nil, errors.New("待创建用户凭据解密失败，请检查原 credentials.key")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var client Record
	if decoder.Decode(&client) != nil || client == nil {
		return nil, errors.New("待创建用户凭据格式无效")
	}
	return client, nil
}

func credentialField(row, user Record) string {
	protocol := value(row["protocol"])
	if protocol == "hysteria" || protocol == "hysteria2" && value(user["auth"]) != "" {
		return "auth"
	}
	if protocol == "trojan" || protocol == "hysteria2" {
		return "password"
	}
	return "id"
}
func FindUser(row, binding Record, missingOK bool) (Record, error) {
	email, valid := binding["userEmail"].(string)
	if !valid || email == "" {
		return nil, errors.New("用户绑定 email 无效")
	}
	endpoint, err := EndpointIdentity(row)
	if err != nil {
		return nil, err
	}
	if endpoint != binding["identityHash"] {
		return nil, errors.New("远端入站身份已变化，停止用户操作")
	}
	model, err := object(row["settings"])
	if err != nil {
		return nil, err
	}
	clients, ok := model["clients"].([]any)
	_, hasClients := model["clients"]
	if !ok && hasClients {
		return nil, errors.New("入站用户列表格式无效")
	}
	matches := []Record{}
	for _, value := range clients {
		client, err := object(value)
		if err != nil {
			return nil, err
		}
		if address, ok := client["email"].(string); ok && address == email {
			matches = append(matches, client)
		}
	}
	if len(matches) == 0 && missingOK {
		return nil, nil
	}
	if len(matches) != 1 {
		return nil, errors.New("远端用户身份已变化或缺失，停止用户操作")
	}
	user := matches[0]
	hash, err := UserIdentity(user)
	if err != nil {
		return nil, err
	}
	if hash != binding["userHash"] {
		return nil, errors.New("远端用户身份已变化，停止用户操作")
	}
	field := credentialField(row, user)
	secret := value(user[field])
	if secret == "" {
		return nil, errors.New("认证凭据缺失")
	}
	count := 0
	for _, value := range clients {
		client, err := object(value)
		if err != nil {
			return nil, err
		}
		if client[field] == secret {
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("认证凭据被共用，停止操作以免影响其他用户")
	}
	return user, nil
}
func NewUser(row Record) (Record, error) {
	protocol := value(row["protocol"])
	if protocol != "vless" && protocol != "vmess" && protocol != "trojan" && protocol != "hysteria" && protocol != "hysteria2" && protocol != "tuic" {
		return nil, errors.New("该协议不支持共用入站独立用户")
	}
	random := make([]byte, 64)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	user := Record{"email": "mxioc-" + hex.EncodeToString(random[:12]), "enable": true, "totalGB": 0, "expiryTime": 0, "limitIp": 0, "subId": hex.EncodeToString(random[12:20])}
	if protocol == "vless" || protocol == "vmess" || protocol == "tuic" {
		id := append([]byte(nil), random[20:36]...)
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		encoded := hex.EncodeToString(id)
		user["id"] = encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:]
	}
	if protocol == "trojan" || protocol == "hysteria2" || protocol == "tuic" {
		user["password"] = base64.RawURLEncoding.EncodeToString(random[36:60])
	}
	if protocol == "hysteria" {
		model, err := object(row["settings"])
		if err != nil {
			return nil, err
		}
		if v := value(model["version"]); v != "" && v != "2" {
			return nil, errors.New("仅支持 Hysteria2 入站")
		}
		user["auth"] = base64.RawURLEncoding.EncodeToString(random[36:60])
	}
	if protocol == "vless" {
		model, err := object(row["settings"])
		if err != nil {
			return nil, err
		}
		clients, _ := model["clients"].([]any)
		enabled := false
		for _, value := range clients {
			client, err := object(value)
			if err != nil {
				return nil, err
			}
			if client["enable"] == false {
				continue
			}
			enabled = true
			flow := valueString(client["flow"])
			if raw, present := client["flow"]; present && raw != nil {
				if _, ok := raw.(string); !ok {
					return nil, errors.New("现有 VLESS flow 格式无效")
				}
			}
			if flow != "" && flow != "xtls-rprx-vision" && flow != "xtls-rprx-vision-udp443" {
				return nil, errors.New("现有 VLESS flow 未适配")
			}
			if flow != "" {
				user["flow"] = flow
			}
			break
		}
		if !enabled {
			stream, err := object(row["streamSettings"])
			if err != nil {
				return nil, err
			}
			network := valueString(stream["network"])
			if stream["security"] == "reality" && (network == "" || network == "tcp" || network == "raw") {
				user["flow"] = "xtls-rprx-vision"
			}
		}
	}
	return user, nil
}
func valueString(v any) string { return value(v) }

func CheckEmailNamespace(rows []Record, email string) error {
	if email == "" {
		return errors.New("独立用户 email 不能为空")
	}
	count := 0
	for _, row := range rows {
		model, err := object(row["settings"])
		if err != nil {
			return err
		}
		clients, _ := model["clients"].([]any)
		for _, v := range clients {
			client, err := object(v)
			if err != nil {
				return err
			}
			if client["email"] == email {
				count++
			}
		}
	}
	if count > 1 {
		return errors.New("认证用户 email 在多个入站重复，不能独立计量")
	}
	return nil
}

func CheckEmailTarget(rows []Record, inboundID, email string) error {
	for _, row := range rows {
		if value(row["id"]) == inboundID {
			continue
		}
		model, err := object(row["settings"])
		if err != nil {
			return err
		}
		clients, _ := model["clients"].([]any)
		for _, v := range clients {
			client, err := object(v)
			if err != nil {
				return err
			}
			if address, ok := client["email"].(string); ok && address == email {
				return errors.New("用户 email 已存在于其他入站，不能添加或操作")
			}
		}
	}
	return nil
}
func UserCounters(row, binding Record) (Record, error) {
	if _, err := FindUser(row, binding, false); err != nil {
		return nil, err
	}
	stats, ok := row["clientStats"].([]any)
	if !ok {
		return nil, errors.New("缺少独立用户流量计数，不能使用共用入站总流量计费")
	}
	var reading Record
	count := 0
	for _, v := range stats {
		entry, err := object(v)
		if err != nil {
			return nil, err
		}
		if entry["email"] == binding["userEmail"] {
			reading = entry
			count++
		}
	}
	if count != 1 {
		return nil, errors.New("认证用户流量计数缺失或重复，等待下次采集")
	}
	result := Record{"source": "authenticated-client"}
	for _, key := range []string{"up", "down"} {
		switch reading[key].(type) {
		case int, int64, json.Number:
		default:
			return nil, errors.New("用户流量计数必须为整数")
		}
		n, err := strconv.ParseInt(value(reading[key]), 10, 64)
		if err != nil || n < 0 {
			return nil, errors.New("用户流量计数无效")
		}
		result[key] = n
	}
	return result, nil
}

// SubscriptionUser is an internal controller operation. Its binding must come
// from durable ownership state; it is not exposed as an arbitrary API payload.
func (m *Manager) SubscriptionUser(ctx context.Context, id string, binding Record, operation string, proposed Record) (Record, error) {
	if binding["scope"] != "user" || binding["serverId"] != id {
		return nil, errors.New("独立用户绑定范围或服务器不匹配")
	}
	inboundID, err := strconv.Atoi(value(binding["inboundId"]))
	if err != nil || inboundID < 1 {
		return nil, errors.New("绑定入站 ID 无效")
	}
	if operation == "read" || operation == "remove" || operation == "pause" || operation == "resume" {
		record, err := m.Record(id)
		if err != nil {
			return nil, err
		}
		if _, err := corePath(value(record["installType"])); err == nil {
			if operation != "read" {
				return m.changeStandaloneUser(ctx, id, operation, binding)
			}
			return m.readStandaloneUser(ctx, id, binding)
		}
	}
	result, err := m.WithPanel(ctx, id, func(panel *Panel, record Record) (any, error) {
		for _, relay := range anyRecords(record["relays"]) {
			if value(relay["inboundId"]) == strconv.Itoa(inboundID) && relay["status"] != nil && relay["status"] != "active" && (operation == "add" || operation == "resume" || operation == "verify") {
				return nil, errors.New("中转路由尚未确认，暂不创建或恢复用户")
			}
		}
		readRows := func() ([]Record, error) {
			result, err := panel.Request(ctx, "panel/api/inbounds/list", nil, "")
			if err != nil {
				return nil, err
			}
			values, ok := result.([]any)
			if !ok {
				return nil, errors.New("面板入站列表无效")
			}
			rows := []Record{}
			for _, value := range values {
				row, err := object(value)
				if err != nil {
					return nil, err
				}
				rows = append(rows, row)
			}
			return rows, nil
		}
		selectRow := func(rows []Record) (Record, error) {
			for _, row := range rows {
				if value(row["id"]) == strconv.Itoa(inboundID) {
					return row, nil
				}
			}
			return nil, errors.New("远端入站不存在")
		}
		rows, err := readRows()
		if err != nil {
			return nil, err
		}
		if err = CheckEmailNamespace(rows, value(binding["userEmail"])); err != nil {
			return nil, err
		}
		if err = CheckEmailTarget(rows, strconv.Itoa(inboundID), value(binding["userEmail"])); err != nil {
			return nil, err
		}
		row, err := selectRow(rows)
		if err != nil {
			return nil, err
		}
		changeOperation := operation
		if operation == "verify" {
			changeOperation = "read"
		}
		user, err := ChangeUser(ctx, panel, row, binding, changeOperation, proposed)
		if err != nil {
			return nil, err
		}
		if changeOperation != "read" {
			rows, err = readRows()
			if err != nil {
				return nil, errors.New("用户请求已发送，但结果未确认，请重新读取核对")
			}
			if err = CheckEmailNamespace(rows, value(binding["userEmail"])); err != nil {
				return nil, err
			}
			row, err = selectRow(rows)
			if err != nil {
				return nil, err
			}
			if operation == "remove" {
				remaining, err := FindUser(row, binding, true)
				if err != nil {
					return nil, err
				}
				if remaining != nil {
					return nil, errors.New("用户删除尚未生效，请核对面板状态")
				}
				return Record{"removed": true}, nil
			}
			user, err = FindUser(row, binding, false)
			if err != nil {
				return nil, err
			}
			if (operation == "pause" || operation == "resume") && (user["enable"] != false) != (operation == "resume") {
				return nil, errors.New("用户启停尚未生效，请核对面板状态")
			}
		}
		output := Record{"inbound": row, "client": user}
		if (record["installType"] == "x-panel" || row["protocol"] == "hysteria" || row["protocol"] == "hysteria2") && (operation == "add" || operation == "verify" || operation == "resume") && user["enable"] != false {
			runtime, err := syncRuntime(ctx, panel, row, user)
			if err != nil {
				return nil, err
			}
			for key, value := range runtime {
				output[key] = value
			}
		}
		// A newly added user may not have a counter row until its first connection.
		// Report that state explicitly; never manufacture a successful zero reading.
		counters, counterErr := UserCounters(row, binding)
		if counterErr != nil {
			output["counterError"] = counterErr.Error()
		} else {
			output["reading"] = counters
		}
		return output, nil
	})
	if err != nil {
		return nil, err
	}
	return result.(map[string]any), nil
}

// ChangeUser acts only on an authenticated identity, never an inbound's entire
// user list. Interrupted writes are not replayed by the panel transport.
func ChangeUser(ctx context.Context, panel *Panel, row, binding Record, operation string, proposed Record) (Record, error) {
	current, err := FindUser(row, binding, operation == "add" || operation == "remove")
	if err != nil {
		return nil, err
	}
	if operation == "read" {
		return current, nil
	}
	var account Record
	switch operation {
	case "add":
		hash, err := UserIdentity(proposed)
		if err != nil || hash != binding["userHash"] {
			return nil, errors.New("待创建用户身份不匹配")
		}
		if current != nil {
			return current, nil
		}
		if proposed["email"] != binding["userEmail"] {
			return nil, errors.New("待创建用户 email 不匹配")
		}
		model, err := object(row["settings"])
		if err != nil {
			return nil, err
		}
		clients, _ := model["clients"].([]any)
		field := credentialField(row, proposed)
		secret := value(proposed[field])
		if secret == "" {
			return nil, errors.New("待创建用户缺少认证凭据")
		}
		for _, value := range clients {
			other, err := object(value)
			if err != nil {
				return nil, err
			}
			if other[field] == secret {
				return nil, errors.New("认证凭据重复，未添加用户")
			}
		}
		account = proposed
	case "remove":
		if current == nil {
			return Record{"removed": true}, nil
		}
		account = current
	case "pause", "resume":
		desired := operation == "resume"
		enabled := current["enable"] != false
		if enabled == desired {
			return current, nil
		}
		account = Record{}
		for key, v := range current {
			account[key] = v
		}
		account["enable"] = desired
	default:
		return nil, errors.New("用户操作无效")
	}
	id, err := strconv.Atoi(value(row["id"]))
	if err != nil || id < 1 {
		return nil, errors.New("远端入站 ID 无效")
	}
	payload := Record{"id": row["id"], "protocol": row["protocol"], "settings": Record{"clients": []any{account}}}
	credential := strings.ReplaceAll(url.QueryEscape(value(account[credentialField(row, account)])), "+", "%20")
	path := "panel/api/inbounds/addClient"
	if operation == "remove" {
		path = "panel/api/inbounds/" + strconv.Itoa(id) + "/delClient/" + credential
		payload = Record{}
	} else if operation == "pause" || operation == "resume" {
		path = "panel/api/inbounds/updateClient/" + credential
	}
	if _, err = panel.Request(ctx, path, payload, ""); err != nil {
		var status panelStatus
		if !errors.As(err, &status) || status.Code != 404 {
			return nil, err
		}
		// Only an explicit missing route permits protocol fallback. An
		// interrupted request may have applied, and must never be replayed.
		email := strings.ReplaceAll(url.QueryEscape(value(binding["userEmail"])), "+", "%20")
		modernPayload := Record{"inboundIds": []int{id}}
		modernPath := "panel/api/clients/" + email + "/detach"
		if operation == "add" {
			modernPath = "panel/api/clients/add"
			modernPayload["client"] = account
		} else if operation == "pause" || operation == "resume" {
			details, readErr := panel.Request(ctx, "panel/api/clients/get/"+email, nil, "")
			if readErr != nil {
				return nil, readErr
			}
			model, ok := details.(map[string]any)
			ids, valid := model["inboundIds"].([]any)
			if !ok || !valid || len(ids) != 1 || value(ids[0]) != strconv.Itoa(id) {
				return nil, errors.New("新版面板用户关联了多个入站，停止全局启停")
			}
			modernPath = "panel/api/clients/update/" + email
			modernPayload = account
		}
		if _, err = panel.RequestJSON(ctx, modernPath, modernPayload); err != nil {
			return nil, err
		}
	}
	if operation == "remove" {
		return Record{"removed": true}, nil
	}
	return account, nil
}
