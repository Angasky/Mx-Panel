package subscriptions

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/config"
	"github.com/Angasky/dingzhi-ban/internal/remote"
)

type fakeBackend struct {
	mu                                              sync.Mutex
	sealer                                          *remote.Manager
	rows                                            []Record
	stats                                           map[string]Record
	adds                                            int
	failBefore, failAfter, offline, missingCounters bool
	ops                                             []string
}

func clone(t any) Record {
	data, _ := json.Marshal(t)
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	var row Record
	_ = decoder.Decode(&row)
	return row
}
func (b *fakeBackend) Record(id string) (Record, error) {
	return Record{"id": id, "installType": "3x-ui", "host": "192.0.2.1"}, nil
}
func (b *fakeBackend) SealUser(user Record) (string, error) { return b.sealer.SealUser(user) }
func (b *fakeBackend) OpenUser(s string) (Record, error)    { return b.sealer.OpenUser(s) }
func (b *fakeBackend) Inbounds(ctx context.Context, id string) (Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.offline {
		return nil, errors.New("offline")
	}
	rows := []any{}
	for _, r := range b.rows {
		rows = append(rows, clone(r))
	}
	return Record{"inbounds": rows}, nil
}
func (b *fakeBackend) SubscriptionUser(ctx context.Context, id string, binding Record, operation string, user Record) (Record, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ops = append(b.ops, operation)
	if b.offline {
		return nil, errors.New("offline")
	}
	var row Record
	for _, r := range b.rows {
		if text(r["id"]) == text(binding["inboundId"]) {
			row = r
			break
		}
	}
	if row == nil {
		return nil, errors.New("missing")
	}
	current, err := remote.FindUser(row, binding, operation == "add" || operation == "remove")
	if err != nil {
		return nil, err
	}
	settings := row["settings"].(Record)
	clients := settings["clients"].([]any)
	if operation == "add" && current == nil {
		if b.failBefore {
			return nil, errors.New("failure before apply")
		}
		b.adds++
		current = clone(user)
		settings["clients"] = append(clients, current)
		b.stats[text(current["email"])] = Record{"up": int64(0), "down": int64(0), "source": "authenticated-client"}
		if b.failAfter {
			return nil, errors.New("failure after apply")
		}
	}
	if operation == "remove" {
		next := []any{}
		for _, v := range clients {
			client := v.(map[string]any)
			if client["email"] != binding["userEmail"] {
				next = append(next, client)
			}
		}
		settings["clients"] = next
		return Record{"removed": true}, nil
	}
	if current == nil {
		return nil, errors.New("missing user")
	}
	if operation == "pause" || operation == "resume" {
		current["enable"] = operation == "resume"
	}
	result := Record{"inbound": clone(row), "client": clone(current)}
	if !b.missingCounters {
		result["reading"] = clone(b.stats[text(current["email"])])
	}
	return result, nil
}
func controllerFixture(t *testing.T) (*Controller, *fakeBackend, string) {
	t.Helper()
	root := t.TempDir()
	file := filepath.Join(root, "config.yaml")
	if err := os.WriteFile(file, []byte("proxies: []\nproxy-groups:\n- name: Proxy\n  type: select\n  proxies: [DIRECT]\nrules: [MATCH,Proxy]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	index := Record{"profiles": []any{Record{"id": "clash", "name": "fixture", "slug": strings.Repeat("a", 50), "files": []string{file}}}, "unknown": json.Number("9007199254740993")}
	data, _ := json.Marshal(index)
	if err := os.WriteFile(filepath.Join(root, "profiles.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	sealer, err := remote.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	b := &fakeBackend{sealer: sealer, stats: map[string]Record{}}
	for i := 1; i <= 3; i++ {
		b.rows = append(b.rows, Record{"id": i, "port": 24000 + i, "protocol": "hysteria", "enable": true, "remark": "shared", "settings": Record{"version": 2, "clients": []any{}}, "streamSettings": Record{"security": "tls", "network": "hysteria", "tlsSettings": Record{"serverName": "cdn.example.com"}}})
	}
	c := New(&config.Repository{Root: root}, b)
	c.started.Store(true)
	c.Now = func() time.Time { return time.Unix(1800000000, 0).UTC() }
	return c, b, root
}
func stateBinding(t *testing.T, c *Controller) Record {
	t.Helper()
	p, err := c.Repository.State("clash")
	if err != nil {
		t.Fatal(err)
	}
	return objects(p["remoteNodes"])[0]
}
func TestBatchPersistsAndImportsDistinctUsers(t *testing.T) {
	c, b, root := controllerFixture(t)
	result, err := c.Batch(context.Background(), "clash", "s", []int{1, 2, 3})
	if err != nil || result["succeeded"] != 3 {
		t.Fatal(result, err)
	}
	snapshot, err := c.Repository.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 3 {
		t.Fatal("nodes missing after successful import", err)
	}
	group := snapshot["groups"].([]any)[0].(map[string]any)["config"].(map[string]any)
	if len(group["proxies"].([]any)) != 4 {
		t.Fatal("nodes not added to selector")
	}
	secrets := map[string]bool{}
	for _, row := range b.rows {
		user := row["settings"].(Record)["clients"].([]any)[0].(map[string]any)
		secrets[text(user["auth"])] = true
	}
	if len(secrets) != 3 {
		t.Fatal("credentials shared")
	}
	data, _ := os.ReadFile(filepath.Join(root, "profiles.json"))
	for secret := range secrets {
		if strings.Contains(string(data), secret) {
			t.Fatal("plaintext pending secret in index")
		}
	}
	p, _ := c.Repository.State("clash")
	if traffic(p)["enforce"] != true || traffic(p)["enabled"] != true {
		t.Fatal("protection not enabled")
	}
	result, err = c.Batch(context.Background(), "clash", "s", []int{1, 2, 3})
	if err != nil || result["existing"] != 3 || b.adds != 3 {
		t.Fatal("retry duplicated users/nodes", result, err)
	}
	reopened := &config.Repository{Root: root}
	snap, err := reopened.Snapshot("clash")
	if err != nil || len(snap["nodes"].([]any)) != 3 {
		t.Fatal("restart lost imported nodes")
	}
}
func TestCreationRecoveryAcrossRestartBeforeAndAfterApply(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(map[bool]string{false: "before", true: "after"}[after], func(t *testing.T) {
			c, b, root := controllerFixture(t)
			b.failAfter = after
			b.failBefore = !after
			result, err := c.Batch(context.Background(), "clash", "s", []int{1})
			if err != nil || result["failed"] != 1 {
				t.Fatal(result, err)
			}
			binding := stateBinding(t, c)
			if binding["status"] != "provisioning" || text(binding["pendingUser"]) == "" {
				t.Fatal("lost durable intent")
			}
			user, err := b.OpenUser(text(binding["pendingUser"]))
			if err != nil {
				t.Fatal(err)
			}
			bytes, _ := os.ReadFile(filepath.Join(root, "profiles.json"))
			if strings.Contains(string(bytes), text(user["auth"])) {
				t.Fatal("unencrypted pending user")
			}
			if err = c.Repository.DeleteProfile("clash"); err == nil {
				t.Fatal("pending profile deleted")
			}
			if _, err = c.Repository.CreateProfile(Record{"name": "copy", "templateId": "clash"}); err == nil {
				t.Fatal("pending credential copied")
			}
			b.failBefore = false
			b.failAfter = false
			c = New(&config.Repository{Root: root}, b)
			c.started.Store(true)
			result, err = c.Batch(context.Background(), "clash", "s", []int{1})
			if err != nil || result["succeeded"] != 1 || b.adds != 1 {
				t.Fatal("recovery allocated new user", result, err, b.adds)
			}
			stored := b.rows[0]["settings"].(Record)["clients"].([]any)[0].(map[string]any)
			if stored["auth"] != user["auth"] {
				t.Fatal("pending credentials changed")
			}
			if _, exists := stateBinding(t, c)["pendingUser"]; exists {
				t.Fatal("completed encrypted intent retained")
			}
		})
	}
}
func TestAccountingUsesUserCountersAndKeepsFractionalRemainders(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	binding := stateBinding(t, c)
	email := text(binding["userEmail"])
	if err = c.Repository.UpdateState("clash", func(p Record) error { objects(p["remoteNodes"])[0]["multiplierUnits"] = int64(500); return nil }); err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		b.stats[email]["up"] = int64(i)
		if _, err = c.Sync(context.Background(), "clash"); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := c.Info("clash")
	if info["used"] != int64(1) {
		t.Fatal("fractional bytes overcharged", info["used"])
	}
	for i := 0; i < 4; i++ {
		_, _ = c.Sync(context.Background(), "clash")
	}
	info, _ = c.Info("clash")
	if info["used"] != int64(1) {
		t.Fatal("idle counters grew")
	}
	b.missingCounters = true
	b.rows[0]["up"] = int64(99999999)
	_, _ = c.Sync(context.Background(), "clash")
	info, _ = c.Info("clash")
	if info["used"] != int64(1) || !strings.Contains(text(info["enforcementError"]), "认证用户计数") {
		t.Fatal("used inbound aggregate or hid counter failure")
	}
	if _, err = c.SetMultiplier(context.Background(), "clash", "s", 1, 1000); err == nil {
		t.Fatal("changed multiplier without successful settlement")
	}
}
func TestExpiryRevokesOnlyOwnedUserEvenWithoutCounters(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	settings := b.rows[0]["settings"].(Record)
	settings["clients"] = append(settings["clients"].([]any), Record{"email": "peer", "auth": "peer-secret", "enable": true})
	_ = c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["expire"] = int64(1); return nil })
	b.missingCounters = true
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	clients := settings["clients"].([]any)
	if len(clients) != 1 || clients[0].(Record)["email"] != "peer" {
		t.Fatal("removed peer or left expired user")
	}
	p, _ := c.Repository.State("clash")
	if p["accessRevoked"] != true || objects(p["remoteNodes"])[0]["status"] != "revoked" {
		t.Fatal("revocation not durable")
	}
	if _, err = c.Batch(context.Background(), "clash", "s", []int{1}); err == nil {
		t.Fatal("revoked subscription granted another user")
	}
}
func TestMonthlyPauseResetAndResumePreserveManualDisabledUsers(t *testing.T) {
	c, b, _ := controllerFixture(t)
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2027, 1, 31, 12, 0, 0, 0, time.UTC)
	c.Now = func() time.Time { return now }
	_ = c.Repository.UpdateState("clash", func(p Record) error {
		t := traffic(p)
		t["total"] = int64(10)
		t["resetPeriod"] = "monthly"
		t["cycleAnchor"] = now.Unix()
		t["nextResetAt"] = time.Date(2027, 2, 28, 12, 0, 0, 0, time.UTC).Unix()
		return nil
	})
	email := text(stateBinding(t, c)["userEmail"])
	b.stats[email]["down"] = int64(10)
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	client := b.rows[0]["settings"].(Record)["clients"].([]any)[0].(Record)
	if client["enable"] != false || stateBinding(t, c)["monthlyPaused"] != true || b.rows[0]["enable"] != true {
		t.Fatal("monthly pause affected inbound or not durable")
	}
	now = time.Date(2027, 2, 28, 12, 0, 1, 0, time.UTC)
	b.missingCounters = true
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	if client["enable"] != false {
		t.Fatal("resumed before the new month baseline was confirmed")
	}
	b.missingCounters = false
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	info, _ := c.Info("clash")
	p, _ := c.Repository.State("clash")
	if info["used"] != int64(0) || client["enable"] != true || text(traffic(p)["nextResetAt"]) != text(time.Date(2027, 3, 31, 12, 0, 0, 0, time.UTC).Unix()) {
		t.Fatal("month reset drift, historic charge or resume failure", info, p)
	}
	client["enable"] = false
	b.stats[email]["down"] = int64(20)
	_, _ = c.Sync(context.Background(), "clash")
	if stateBinding(t, c)["monthlyPaused"] == true {
		t.Fatal("adopted manually disabled user for automatic resume")
	}
}

func TestCounterAndStorageFailuresDoNotEraseRecoveryIdentity(t *testing.T) {
	c, b, _ := controllerFixture(t)
	b.failBefore = true
	_, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil {
		t.Fatal(err)
	}
	before := stateBinding(t, c)
	_, _ = c.Sync(context.Background(), "clash")
	after := stateBinding(t, c)
	if after["status"] != "provisioning" || after["pendingUser"] != before["pendingUser"] {
		t.Fatal("sampler discarded pending creation")
	}
	b.failBefore = false
	result, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil || result["succeeded"] != 1 {
		t.Fatal(result, err)
	}
	_ = c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["upload"] = json.Number("9223372036854775807"); return nil })
	email := text(stateBinding(t, c)["userEmail"])
	b.stats[email]["up"] = int64(1)
	_, _ = c.Sync(context.Background(), "clash")
	if stateBinding(t, c)["up"] != json.Number("0") {
		t.Fatal("overflow advanced baseline without recording usage")
	}
}
func TestConcurrentImportAndIdentityChange(t *testing.T) {
	c, b, _ := controllerFixture(t)
	var group sync.WaitGroup
	for i := 0; i < 6; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			result, err := c.Batch(context.Background(), "clash", "s", []int{1})
			if err != nil || result["succeeded"] != 1 {
				t.Error(result, err)
			}
		}()
	}
	group.Wait()
	if b.adds != 1 {
		t.Fatal("concurrent duplicate remote users")
	}
	b.rows[0]["port"] = 24555
	_ = c.Repository.UpdateState("clash", func(p Record) error { traffic(p)["expire"] = int64(1); return nil })
	_, _ = c.Sync(context.Background(), "clash")
	if len(b.rows[0]["settings"].(Record)["clients"].([]any)) != 1 {
		t.Fatal("identity replacement was deleted")
	}
	if stateBinding(t, c)["status"] != "active" {
		t.Fatal("ambiguous identity lost ownership record")
	}
}
