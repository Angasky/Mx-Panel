package config

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// BindingToken identifies a generation, excluding mutable billing samples.
func BindingToken(profile string, binding Document) string {
	values := []any{profile}
	for _, key := range []string{"serverId", "inboundId", "port", "identityHash", "boundAt", "name", "userEmail", "userHash", "operationId"} {
		values = append(values, binding[key])
	}
	data, _ := json.Marshal(values)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func bindingErrors(record Document) {
	messages := []string{}
	seen := map[string]bool{}
	for _, v := range rows(record, "remoteNodes") {
		b := v.(map[string]any)
		message := stringValue(b["error"])
		if message != "" && !seen[message] {
			seen[message] = true
			messages = append(messages, message)
		}
	}
	message := []rune(strings.Join(messages, "；"))
	if len(message) > 1500 {
		message = message[:1500]
	}
	record["enforcementError"] = string(message)
}

// Preserve durable recovery evidence during bulk history cleanup. Explicit
// individual removal remains a separate, confirmed abandonment operation.
func BindingCleanupPending(binding Document) bool {
	return binding["inboundDeletePending"] != nil || binding["localCleanupPending"] == true
}

func (r *Repository) CleanupBindings(id string, confirmed bool) (int, error) {
	if !confirmed {
		return 0, errors.New("请确认仅清理本地绑定记录，远端节点将保留")
	}
	removed := 0
	err := r.UpdateState(id, func(p Document) error {
		keep := []any{}
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if BindingCleanupPending(b) {
				keep = append(keep, v)
				continue
			}
			switch b["status"] {
			case "detached", "revoked", "missing", "identity_changed":
				removed++
			default:
				keep = append(keep, v)
			}
		}
		p["remoteNodes"] = keep
		bindingErrors(p)
		return nil
	})
	return removed, err
}

func (r *Repository) RemoveBinding(id string, index int, token string, confirmed bool) error {
	raw, err := hex.DecodeString(token)
	if !confirmed || index < 0 || err != nil || len(raw) != 32 {
		return errors.New("请确认并刷新要移除的绑定记录")
	}
	return r.UpdateState(id, func(p Document) error {
		bindings := rows(p, "remoteNodes")
		if index >= len(bindings) {
			return errors.New("绑定记录已变化，请刷新")
		}
		expected := BindingToken(stringValue(p["id"]), bindings[index].(map[string]any))
		if subtle.ConstantTimeCompare([]byte(token), []byte(expected)) != 1 {
			return errors.New("绑定记录已变化，请刷新")
		}
		p["remoteNodes"] = append(bindings[:index], bindings[index+1:]...)
		bindingErrors(p)
		return nil
	})
}

// DetachServer holds the index lock across the local registry commit, allowing
// rollback without overwriting concurrent quota edits. The callback must not do IO
// against a remote server or acquire another repository lock.
func (r *Repository) DetachServer(server string, confirmed bool, commit func() error) (Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	path := filepath.Join(r.Root, "profiles.json")
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	count := 0
	for _, v := range rows(index, "profiles") {
		p := v.(map[string]any)
		for _, v := range rows(p, "remoteNodes") {
			b := v.(map[string]any)
			if b["serverId"] == server && (b["status"] == "active" || b["status"] == "provisioning") {
				if !confirmed {
					return nil, errors.New("服务器存在订阅绑定，请确认解除本地绑定并保留远端节点")
				}
				b["status"], b["detachedAt"] = "detached", time.Now().Unix()
				count++
			}
		}
	}
	if count > 0 {
		if err = r.writeIndex(index); err != nil {
			return nil, err
		}
	}
	if err = commit(); err != nil {
		if count > 0 {
			err = errors.Join(err, atomic(path, original))
		}
		return nil, err
	}
	return Document{"detachedBindings": count, "remotePreserved": true}, nil
}
