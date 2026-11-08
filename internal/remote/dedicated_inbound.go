package remote

import (
	"context"
	"errors"
	"strconv"
)

// DedicatedPasswordBinding identifies a whole single-password Shadowsocks
// inbound. It cannot be confused with authenticated-client accounting.
func DedicatedPasswordBinding(row, binding Record) (Record, error) {
	if row == nil {
		return nil, errors.New("专属入站不存在")
	}
	settings, err := inboundObject(row["settings"])
	if err != nil {
		return nil, err
	}
	if raw, exists := settings["clients"]; exists {
		clients, ok := raw.([]any)
		if !ok || len(clients) != 0 {
			return nil, errors.New("单密码专属入站不能包含用户列表")
		}
	}
	switch row["protocol"] {
	case "shadowsocks":
		if value(settings["password"]) == "" {
			return nil, errors.New("单密码入站缺少凭据")
		}
		if _, exists := settings["users"]; exists {
			return nil, errors.New("单密码入站含其他用户模型")
		}
	case "http", "socks":
		if raw, exists := settings["accounts"]; exists {
			accounts, ok := raw.([]any)
			if !ok || len(accounts) > 1 {
				return nil, errors.New("专属代理入站不能包含多个账号")
			}
			for _, raw := range accounts {
				if _, ok := raw.(Record); !ok {
					return nil, errors.New("代理账号格式无效")
				}
			}
		}
	default:
		return nil, errors.New("该入站不属于专属单连接代理")
	}
	hash, err := LegacyInboundIdentity(row)
	if err != nil {
		return nil, err
	}
	endpoint, err := EndpointIdentity(row)
	if err != nil {
		return nil, err
	}
	if expected := value(binding["identityHash"]); expected != "" && expected != hash {
		return nil, errors.New("专属入站凭据或配置已变化")
	}
	if expected := value(binding["dedicatedEndpointHash"]); expected != "" && expected != endpoint {
		return nil, errors.New("专属入站传输配置已变化")
	}
	result := Record{}
	for key, value := range binding {
		result[key] = value
	}
	result["scope"], result["dedicated"], result["identityHash"], result["dedicatedEndpointHash"] = "inbound", true, hash, endpoint
	return result, nil
}
func dedicatedPasswordReading(row Record) (Record, error) {
	result := Record{"source": "inbound"}
	for _, key := range []string{"up", "down"} {
		n, err := strconv.ParseInt(value(row[key]), 10, 64)
		if err != nil || n < 0 {
			return nil, errors.New("专属入站计数缺失或无效")
		}
		result[key] = n
	}
	return result, nil
}

func (m *Manager) DedicatedInbound(ctx context.Context, server string, binding Record, operation string) (Record, error) {
	if binding["scope"] != "inbound" || binding["dedicated"] != true || binding["serverId"] != server || len(value(binding["identityHash"])) != 64 || len(value(binding["dedicatedEndpointHash"])) != 64 {
		return nil, errors.New("专属入站归属无效")
	}
	id, err := strconv.Atoi(value(binding["inboundId"]))
	if err != nil || id < 1 {
		return nil, errors.New("入站 ID 无效")
	}
	record, err := m.Record(server)
	if err != nil {
		return nil, err
	}
	if kind := value(record["installType"]); kind == "xray" || kind == "sing-box" {
		return m.withCore(ctx, server, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
			return m.dedicatedCore(ctx, server, kind, record, binding, operation, run)
		})
	}
	if operation != "read" && operation != "pause" && operation != "resume" && operation != "remove" {
		return nil, errors.New("专属入站操作无效")
	}
	result, err := m.WithPanel(ctx, server, func(p *Panel, record Record) (any, error) {
		if operation == "remove" {
			row, present, err := panelInbound(ctx, p, id)
			if err != nil {
				return nil, err
			}
			if present {
				if _, err := DedicatedPasswordBinding(row, binding); err != nil {
					return nil, err
				}
			}
			port, err := parsedPort(binding["port"], 0)
			if err != nil || port == 0 {
				return nil, errors.New("专属入站端口无效")
			}
			// Clear only resources registered for this verified dedicated endpoint.
			for _, field := range []string{"bandwidths", "meters"} {
				resources, err := inboundObject(record[field])
				if err != nil {
					return nil, err
				}
				if _, exists := resources[strconv.Itoa(id)]; exists {
					if field == "bandwidths" {
						err = m.clearLegacyBandwidth(ctx, record, id, port, p.run)
					} else {
						err = m.clearLegacyMeter(ctx, record, id, port, p.run)
					}
					if err != nil {
						return nil, err
					}
					record, err = m.Record(server)
					if err != nil {
						return nil, err
					}
				}
			}
		}
		return dedicatedPanelInbound(ctx, p, record, id, binding, operation)
	})
	if err != nil {
		return nil, err
	}
	return result.(Record), nil
}
func dedicatedPanelInbound(ctx context.Context, p *Panel, record Record, id int, binding Record, operation string) (Record, error) {
	row, present, err := panelInbound(ctx, p, id)
	if err != nil {
		return nil, err
	}
	if !present {
		if operation == "remove" {
			return Record{"removed": true}, nil
		}
		return nil, errors.New("专属入站缺失")
	}
	if _, err := DedicatedPasswordBinding(row, binding); err != nil {
		return nil, err
	}
	version, err := InboundVersion(row)
	if err != nil {
		return nil, err
	}
	if operation == "remove" {
		_, err := deletePanelInbound(ctx, p, record, id, version, func(old Record) error {
			if old == nil {
				return nil
			}
			_, err := DedicatedPasswordBinding(old, binding)
			return err
		})
		if err != nil {
			return nil, err
		}
		return Record{"removed": true}, nil
	}
	if operation == "pause" || operation == "resume" {
		enabled := operation == "resume"
		if row["enable"] != enabled {
			if _, err := editPanelInbound(ctx, p, record, id, Record{"enable": enabled}, version, func(old, next Record) error {
				_, err := DedicatedPasswordBinding(old, binding)
				if err != nil {
					return err
				}
				_, err = DedicatedPasswordBinding(next, binding)
				return err
			}); err != nil {
				return nil, err
			}
			row, present, err = panelInbound(ctx, p, id)
			if err != nil || !present {
				return nil, errors.New("专属入站启停结果待核对")
			}
			if _, err := DedicatedPasswordBinding(row, binding); err != nil {
				return nil, err
			}
		}
	}
	reading, err := dedicatedPasswordReading(row)
	if err != nil {
		return nil, err
	}
	return Record{"inbound": row, "client": Record{"enable": row["enable"]}, "reading": reading}, nil
}
