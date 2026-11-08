package web

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/storage"
)

const sessionTTL = 12 * time.Hour
const sessionLimit = 8

type savedSessions struct {
	Version    int                `json:"version"`
	Credential string             `json:"credential"`
	Entries    map[string]session `json:"entries"`
}

func credentialID(auth account) string {
	data, _ := json.Marshal(auth)
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

// Sessions are part of the credential transaction: password changes invalidate
// every session in the same atomic rename, even if the process stops immediately.
func readSessions(doc map[string]any, auth account, now time.Time) (map[[32]byte]session, error) {
	out := map[[32]byte]session{}
	value, exists := doc["goSessions"]
	if !exists {
		return out, nil
	} // Python sessions require a new login once.
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	var saved savedSessions
	if json.Unmarshal(data, &saved) != nil || saved.Version != 1 || saved.Credential == "" || saved.Entries == nil || len(saved.Entries) > sessionLimit {
		return nil, errors.New("持久化登录会话格式无效")
	}
	if saved.Credential != credentialID(auth) {
		return out, nil
	}
	for digest, value := range saved.Entries {
		raw, err := hex.DecodeString(digest)
		if err != nil || len(raw) != 32 || value.Created.IsZero() || !value.Expires.After(value.Created) || value.Expires.Sub(value.Created) > sessionTTL || value.Created.After(now.Add(5*time.Minute)) {
			return nil, errors.New("持久化登录会话记录无效")
		}
		if now.Before(value.Expires) {
			out[[32]byte(raw)] = value
		}
	}
	return out, nil
}

func encodeSessions(auth account, entries map[[32]byte]session) savedSessions {
	saved := savedSessions{Version: 1, Credential: credentialID(auth), Entries: map[string]session{}}
	for key, value := range entries {
		saved.Entries[hex.EncodeToString(key[:])] = value
	}
	return saved
}

// Caller holds s.mu. Read the latest disk state and publish memory only after a
// successful durable write. Session plaintext is never written to the file.
func (s *Server) updateSessions(change func(map[[32]byte]session)) error {
	var next map[[32]byte]session
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
		next, err = readSessions(doc, s.account, s.now())
		if err != nil {
			return err
		}
		change(next)
		doc["goSessions"] = encodeSessions(s.account, next)
		return nil
	})
	if err == nil {
		s.sessions = next
	}
	return err
}

func addSession(entries map[[32]byte]session, key [32]byte, now time.Time) {
	if len(entries) >= sessionLimit {
		var oldest [32]byte
		var stamp time.Time
		for candidate, value := range entries {
			if stamp.IsZero() || value.Created.Before(stamp) {
				oldest, stamp = candidate, value.Created
			}
		}
		delete(entries, oldest)
	}
	entries[key] = session{Created: now, Expires: now.Add(sessionTTL)}
}

// Caller holds s.mu. Credential upgrades, failure cleanup and the new session
// share one durable transaction. Existing sessions survive a hash-only upgrade.
func (s *Server) completeLogin(auth, upgraded account, keys []string, token [32]byte) error {
	var sessions map[[32]byte]session
	var failures map[string]failure
	err := storage.New(s.options.AuthFile).Update(func(doc map[string]any) error {
		raw, err := json.Marshal(doc)
		if err != nil {
			return err
		}
		var disk account
		if err = json.Unmarshal(raw, &disk); err != nil {
			return err
		}
		if disk.Iterations == 0 {
			disk.Iterations = 240000
		}
		if disk != auth {
			return errors.New("账号文件已变化，请重新登录")
		}
		sessions, err = readSessions(doc, auth, s.now())
		if err != nil {
			return err
		}
		failures, err = readLoginFailures(doc, auth, s.now())
		if err != nil {
			return err
		}
		for _, key := range keys {
			delete(failures, key)
		}
		addSession(sessions, token, s.now())
		doc["username"], doc["salt"], doc["hash"], doc["iterations"] = upgraded.Username, upgraded.Salt, upgraded.Hash, upgraded.Iterations
		doc["goSessions"] = encodeSessions(upgraded, sessions)
		doc["goLoginFailures"] = savedLoginFailures{Version: 1, Credential: credentialID(upgraded), Entries: failures}
		return nil
	})
	if err == nil {
		s.account, s.sessions, s.failures = upgraded, sessions, failures
	}
	return err
}
