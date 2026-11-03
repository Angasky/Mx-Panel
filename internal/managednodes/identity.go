// Package managednodes verifies ownership before removing local proxy records.
package managednodes

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/Angasky/dingzhi-ban/internal/remote"
)

func text(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprint(v)
}
func Identity(node map[string]any) string {
	h := sha256.New()
	h.Write([]byte("mxioc-node-v1"))
	var size [4]byte
	for _, key := range []string{"type", "server", "port", "uuid", "password", "psk", "username"} {
		data := []byte(text(node[key]))
		binary.BigEndian.PutUint32(size[:], uint32(len(data)))
		h.Write(size[:])
		h.Write(data)
	}
	return hex.EncodeToString(h.Sum(nil))
}
func Owns(binding, node map[string]any) bool {
	refs, _ := binding["importedNodes"].([]any)
	if len(refs) > 0 {
		for _, v := range refs {
			if r, ok := v.(map[string]any); ok && r["identity"] == Identity(node) {
				return true
			}
		}
		return false
	}
	if binding["scope"] != "user" || text(binding["userHash"]) == "" || text(node["port"]) != text(binding["port"]) {
		return false
	}
	kind := text(node["type"])
	client := map[string]any{"email": binding["userEmail"]}
	switch kind {
	case "vless", "vmess":
		client["id"] = node["uuid"]
	case "tuic":
		client["id"] = node["uuid"]
		client["password"] = node["password"]
	case "trojan", "hysteria2":
		client["password"] = node["password"]
	default:
		return false
	}
	for _, flow := range []any{node["flow"], ""} {
		client["flow"] = flow
		hash, err := remote.UserIdentity(client)
		if err == nil && hash == binding["userHash"] {
			return true
		}
		if kind == "hysteria2" {
			auth := map[string]any{"email": binding["userEmail"], "flow": flow, "auth": node["password"]}
			hash, err := remote.UserIdentity(auth)
			if err == nil && hash == binding["userHash"] {
				return true
			}
		}
	}
	return false
}
