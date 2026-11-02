package config

import (
	"errors"
	"fmt"
)

// GuardServerUpdate protects the addresses and credentials' ownership context
// shared by all subscriptions, not just the currently selected subscription.
func (r *Repository) GuardServerUpdate(id string, payload, previous map[string]any) error {
	if id == "" {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	owned := false
	for _, value := range index["profiles"].([]any) {
		record := value.(map[string]any)
		bindings, _ := record["remoteNodes"].([]any)
		for _, value := range bindings {
			binding, ok := value.(map[string]any)
			if ok && binding["serverId"] == id && binding["status"] == "active" {
				owned = true
			}
		}
	}
	if !owned {
		return nil
	}
	for _, key := range []string{"host", "sshPort", "installType", "connectionMode", "domain", "panelAddress"} {
		if value, ok := payload[key]; ok && fmt.Sprint(value) != fmt.Sprint(previous[key]) {
			return errors.New("服务器仍有订阅专属用户，不能变更地址、内核类型或接入模式")
		}
	}
	if payload["clearCoreConfig"] == true || stringValue(payload["coreConfig"]) != "" {
		return errors.New("已有订阅专属用户，不能覆盖远端完整配置")
	}
	return nil
}
