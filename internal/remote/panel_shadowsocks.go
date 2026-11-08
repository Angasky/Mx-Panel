package remote

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// Classic panel Shadowsocks has one server password, not subscription users.
// Validation uses a placeholder port; randomness belongs to the journaled build.
func ValidatePanelShadowsocks(payload Record) error {
	if payload["template"] != "shadowsocks" {
		return errors.New("传统 Shadowsocks 模板无效")
	}
	if _, exists := payload["inbound"]; exists {
		return errors.New("请选择原始配置或 Shadowsocks 模板，不能同时提交")
	}
	port := payload["port"]
	if port == nil || port == "" {
		port = 24001
	}
	_, err := buildInboundTemplate(Record{"template": "vmess-tcp", "port": port, "remark": payload["remark"]}, "")
	return err
}

func buildPanelShadowsocks(payload Record) (Record, error) {
	if err := ValidatePanelShadowsocks(payload); err != nil {
		return nil, err
	}
	row, err := buildInboundTemplate(Record{"template": "vmess-tcp", "port": payload["port"], "remark": payload["remark"]}, "")
	if err != nil {
		return nil, err
	}
	secret := make([]byte, 24)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	row["protocol"] = "shadowsocks"
	row["settings"] = Record{"method": "aes-128-gcm", "password": base64.RawURLEncoding.EncodeToString(secret), "network": "tcp,udp"}
	return row, nil
}
