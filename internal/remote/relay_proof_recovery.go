package remote

import (
	"encoding/hex"
	"errors"
	"maps"
	"strings"
)

var errLegacyRelayProof = errors.New("旧中转缺少可核对的 Go 创建记录，保留远端配置")

func (m *Manager) recoverRelayProof(record, relay, inbound, live Record) (Record, error) {
	m.mu.Lock()
	journal, err := m.createJournal()
	m.mu.Unlock()
	if err != nil {
		return nil, err
	}
	tag := value(relay["outboundTag"])
	suffix, ok := strings.CutPrefix(tag, "mxioc-relay-")
	if _, err := hex.DecodeString(suffix); !ok || len(suffix) != 16 || err != nil ||
		relay["status"] != "active" || relay["deletePending"] == true {
		return nil, errLegacyRelayProof
	}
	server, revision := record["id"], createServerRevision(record)
	id, inboundTag := value(relay["inboundId"]), value(inbound["tag"])
	endpoint, err := EndpointIdentity(inbound)
	if err != nil || inboundTag == "" || value(inbound["id"]) != id {
		return nil, errLegacyRelayProof
	}
	var matched Record
	for key, item := range journal {
		base := item.(Record)
		if len(key) != 64 || !strings.HasPrefix(key, suffix) || base["status"] != "confirmed" ||
			base["serverId"] != server || base["revision"] != revision || value(base["inboundId"]) != id ||
			base["endpointHash"] != endpoint {
			continue
		}
		relayKey, err := identity([]any{key, "relay"})
		if err != nil {
			return nil, err
		}
		entry, _ := journal[relayKey].(Record)
		if entry["status"] != "confirmed" || entry["serverId"] != server || entry["revision"] != revision ||
			entry["scope"] != base["scope"] || entry["requestHash"] != base["requestHash"] {
			continue
		}
		if matched != nil {
			return nil, errLegacyRelayProof
		}
		matched = entry
	}
	if matched == nil {
		return nil, errLegacyRelayProof
	}
	desired, err := m.OpenUser(value(matched["sealedDesired"]))
	if err != nil {
		return nil, err
	}
	original, originalOK := desired["original"].(Record)
	updated, updatedOK := desired["updated"].(Record)
	if !originalOK || !updatedOK || containsConfigString(original, tag) {
		return nil, errLegacyRelayProof
	}
	expected, err := relayOwnership(updated, tag, inboundTag)
	if err != nil {
		return nil, err
	}
	ruleHash, err := identity(Record{"type": "field", "inboundTag": []any{inboundTag}, "outboundTag": tag})
	if err != nil || expected["routeHash"] != ruleHash {
		return nil, errLegacyRelayProof
	}
	actual, err := relayOwnership(live, tag, inboundTag)
	if err != nil || actual["outboundHash"] != expected["outboundHash"] || actual["routeHash"] != expected["routeHash"] {
		return nil, errors.New("远端中转出站或路由已变化，保留远端配置")
	}
	proof := maps.Clone(relay)
	maps.Copy(proof, expected)
	if _, _, err := stripOwnedRelay(live, proof); err != nil {
		return nil, err
	}
	return proof, nil
}
