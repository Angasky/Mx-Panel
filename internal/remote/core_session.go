package remote

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

var ErrServerBusy = errors.New("服务器正在处理其他操作")

type inventoryWaitKey struct{}
type cachedCoreSession struct {
	client   *ssh.Client
	identity [32]byte
	timer    *time.Timer
}

// Only an idle transport is pooled. Every operation still owns the server gate
// and re-reads its registration; credentials and pinned host keys are part of the key.
func (m *Manager) takeCoreSession(ctx context.Context, id string, c Connection) (*ssh.Client, error) {
	raw, _ := json.Marshal(c)
	identity := sha256.Sum256(raw)
	m.mu.Lock()
	cached := m.coreSessions[id]
	if cached != nil {
		delete(m.coreSessions, id)
		cached.timer.Stop()
	}
	m.mu.Unlock()
	if cached != nil {
		if cached.identity == identity {
			return cached.client, nil
		}
		cached.client.Close()
	}
	return Connect(ctx, c)
}
func (m *Manager) keepCoreSession(id string, c Connection, client *ssh.Client) {
	raw, _ := json.Marshal(c)
	entry := &cachedCoreSession{client: client, identity: sha256.Sum256(raw)}
	m.mu.Lock()
	if m.coreSessions == nil {
		m.coreSessions = map[string]*cachedCoreSession{}
	}
	if old := m.coreSessions[id]; old != nil {
		old.timer.Stop()
		old.client.Close()
	}
	if len(m.coreSessions) >= 32 {
		m.mu.Unlock()
		client.Close()
		return
	}
	m.coreSessions[id] = entry
	entry.timer = time.AfterFunc(30*time.Second, func() {
		m.mu.Lock()
		if m.coreSessions[id] == entry {
			delete(m.coreSessions, id)
			entry.client.Close()
		}
		m.mu.Unlock()
	})
	m.mu.Unlock()
}
func (m *Manager) coreGate(ctx context.Context, id string) (chan struct{}, error) {
	m.mu.Lock()
	if m.operations == nil {
		m.operations = map[string]chan struct{}{}
	}
	gate := m.operations[id]
	if gate == nil {
		gate = make(chan struct{}, 1)
		m.operations[id] = gate
	}
	m.mu.Unlock()
	select {
	case gate <- struct{}{}:
		return gate, nil
	default:
	}
	if ctx.Value(inventoryWaitKey{}) != true {
		return nil, ErrServerBusy
	}
	select {
	case gate <- struct{}{}:
		return gate, nil
	case <-ctx.Done():
		return nil, errors.New("服务器操作尚未结束，请稍后刷新节点列表")
	}
}
