package remote

import (
	"encoding/json"
	"errors"
)

// PrepareRawPanelInbound validates a user-supplied panel configuration without
// assigning its existing credentials to a subscription. Unknown panel fields
// are filtered, matching the Python prepare_inbound contract.
func PrepareRawPanelInbound(raw any) (Record, error) {
	input, ok := raw.(map[string]any)
	if !ok || input == nil {
		return nil, errors.New("原始入站配置必须为 JSON 对象")
	}
	next := Record{"enable": true, "remark": "", "listen": "", "up": 0, "down": 0, "total": 0, "expiryTime": 0, "settings": Record{}, "streamSettings": Record{}, "sniffing": Record{}}
	for _, key := range inboundFields {
		if v, exists := input[key]; exists {
			next[key] = v
		}
	}
	// Copy nested input as well: later journal/port handling must never mutate the
	// caller's object or retain aliases to user credentials.
	wire, err := json.Marshal(next)
	if err != nil || len(wire) > 256<<10 {
		return nil, errors.New("单条入站配置不能超过 256 KB")
	}
	next, err = inboundObject(string(wire))
	if err != nil {
		return nil, err
	}
	_, next, err = prepareInboundEdit(next, Record{})
	return next, err
}

func panelCreationPayload(payload Record) (Record, bool, error) {
	raw, exists := payload["inbound"]
	if payload["template"] == "shadowsocks" {
		return nil, true, ValidatePanelShadowsocks(payload)
	}
	if !exists {
		return nil, false, nil
	}
	row, err := PrepareRawPanelInbound(raw)
	return row, true, err
}
