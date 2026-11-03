package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/storage"
)

const loginFailureWindow = 15 * time.Minute
const loginFailureLimit = 4096

type savedLoginFailures struct {
	Version    int                `json:"version"`
	Credential string             `json:"credential"`
	Entries    map[string]failure `json:"entries"`
}

func failureKey(key string) string {
	digest := sha256.Sum256([]byte(key))
	return hex.EncodeToString(digest[:])
}

func readLoginFailures(doc map[string]any, auth account, now time.Time) (map[string]failure, error) {
	entries := map[string]failure{}
	value, exists := doc["goLoginFailures"]
	if !exists {
		return entries, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var saved savedLoginFailures
	if json.Unmarshal(raw, &saved) != nil || saved.Version != 1 || saved.Credential == "" || saved.Entries == nil || len(saved.Entries) > loginFailureLimit {
		return nil, errors.New("持久化登录限流格式无效")
	}
	if saved.Credential != credentialID(auth) {
		return entries, nil
	}
	for key, v := range saved.Entries {
		hash, err := hex.DecodeString(key)
		if err != nil || len(hash) != 32 || v.Count < 1 || v.Count > 5 || v.Since.IsZero() || v.Since.After(now.Add(5*time.Minute)) {
			return nil, errors.New("持久化登录限流记录无效")
		}
		if now.Sub(v.Since) < loginFailureWindow {
			entries[key] = v
		}
	}
	return entries, nil
}

// Caller holds s.mu. Count before password hashing, and persist before admitting
// the attempt. A disk failure never downgrades to an unrecorded login attempt.
// This is a single-process limiter; it does not coordinate multiple Go services.
func (s *Server) persistLoginFailures(next map[string]failure) error {
	err := storage.New(s.options.AuthFile).Update(func(doc map[string]any) error {
		raw, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		var disk account
		if json.Unmarshal(raw, &disk) != nil {
			return errors.New("账号文件格式无效")
		}
		if disk.Iterations == 0 {
			disk.Iterations = 240000
		}
		if disk != s.account {
			return errors.New("账号文件已变化，请重启服务并重新登录")
		}
		doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(s.account), Entries: next}
		return nil
	})
	if err == nil {
		s.failures = next
	}
	return err
}

func copyLoginFailures(entries map[string]failure, now time.Time) map[string]failure {
	next := make(map[string]failure, len(entries))
	for key, v := range entries {
		if now.Sub(v.Since) < loginFailureWindow {
			next[key] = v
		}
	}
	return next
}
