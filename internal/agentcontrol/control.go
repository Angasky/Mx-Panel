// Package agentcontrol implements explicit, locally configured service operations.
// It never accepts executable names, filesystem paths or shell commands from peers.
package agentcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

const MaxConfig = 256 << 10

type Command struct {
	ID       string `json:"id"`
	Target   string `json:"target"`
	Action   string `json:"action"`
	Revision string `json:"revision,omitempty"`
	Content  string `json:"content,omitempty"`
	Expires  int64  `json:"expires"`
}
type Result struct {
	ID       string `json:"id"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	Content  string `json:"content,omitempty"`
	Revision string `json:"revision,omitempty"`
	State    string `json:"state,omitempty"`
}
type Target struct {
	// Paths are configured by the owner in the local 0600 Agent configuration.
	Kind     string `json:"kind"`
	Config   string `json:"config"`
	Binary   string `json:"binary"`
	Service  string `json:"service"`
	Writable bool   `json:"writable"`
}
type Report struct {
	Sample       string   `json:"sample"`
	Capabilities []string `json:"capabilities,omitempty"`
	Result       *Result  `json:"result,omitempty"`
}
type Ack struct {
	OK      bool     `json:"ok"`
	Command *Command `json:"command,omitempty"`
}
type Controller struct {
	mu       sync.Mutex
	Targets  map[string]Target
	StateDir string
	run      func(context.Context, string, ...string) error
}

var identifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func Validate(c Command) error {
	if !regexp.MustCompile(`^[a-f0-9]{32}$`).MatchString(c.ID) || !identifier.MatchString(c.Target) {
		return errors.New("任务或服务标识无效")
	}
	switch c.Action {
	case "read", "status", "validate", "apply", "rollback", "restart", "start", "stop", "reload":
	default:
		return errors.New("不支持的管理操作")
	}
	if len(c.Content) > MaxConfig {
		return errors.New("配置超过 256 KiB")
	}
	if c.Action == "apply" || c.Action == "rollback" {
		if len(c.Revision) != 64 {
			return errors.New("必须先读取配置版本")
		}
	}
	if c.Action != "apply" && c.Action != "validate" && c.Content != "" {
		return errors.New("此操作不能携带配置")
	}
	return nil
}
func (c *Controller) Check() error {
	if len(c.Targets) > 16 {
		return errors.New("最多允许管理 16 个服务")
	}

	if !filepath.IsAbs(c.StateDir) || filepath.Clean(c.StateDir) != c.StateDir || strings.Count(c.StateDir, "/") < 2 || strings.ContainsAny(c.StateDir, "\x00\r\n %\t") {
		return errors.New("管理状态目录必须为绝对路径")
	}
	if info, e := os.Lstat(c.StateDir); e == nil && (!info.IsDir() || info.Mode()&os.ModeSymlink != 0) {
		return errors.New("管理状态目录不能是符号链接或普通文件")
	}
	for name, t := range c.Targets {
		if !identifier.MatchString(name) || !identifier.MatchString(t.Service) {
			return errors.New("管理服务名称无效")
		}
		if t.Kind != "xray" && t.Kind != "sing-box" && t.Kind != "nginx" {
			return errors.New("仅支持 Xray、sing-box、Nginx 管理")
		}
		for _, p := range []string{t.Config, t.Binary} {
			if !filepath.IsAbs(p) || filepath.Clean(p) != p || strings.ContainsAny(p, "\r\n\x00 %\t") {
				return errors.New("管理配置和程序必须使用规范绝对路径")
			}
		}
		if _, e := regular(t.Config); e != nil {
			return errors.New("管理配置必须是已存在的普通文件，不能是符号链接")
		}
		if info, e := os.Stat(t.Binary); e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return errors.New("管理程序不存在或不可执行")
		}
	}
	return nil
}
func regular(path string) (os.FileInfo, error) {
	i, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !i.Mode().IsRegular() {
		return nil, errors.New("不是普通文件")
	}
	return i, nil
}
func read(path string) ([]byte, error) {
	if _, e := regular(path); e != nil {
		return nil, e
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, MaxConfig+1))
	if len(b) > MaxConfig {
		return nil, errors.New("配置超过大小限制")
	}
	return b, e
}
func revision(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func atomic(path string, b []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".mx-agent-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(mode); e != nil {
		return e
	}
	if _, e = f.Write(b); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	return os.Rename(f.Name(), path)
}
func (c *Controller) execute(ctx context.Context, binary string, args ...string) error {
	if c.run != nil {
		return c.run(ctx, binary, args...)
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	// Configuration validators may print credentials. Never return their output.
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	return cmd.Run()
}
func (c *Controller) validate(ctx context.Context, t Target, path string) error {
	switch t.Kind {
	case "xray":
		return c.execute(ctx, t.Binary, "run", "-test", "-format", "json", "-config", path)
	case "sing-box":
		return c.execute(ctx, t.Binary, "check", "-c", path)
	case "nginx":
		return c.execute(ctx, t.Binary, "-t", "-c", path, "-p", filepath.Dir(t.Config)+"/")
	}
	return errors.New("unknown target")
}
func (c *Controller) healthy(ctx context.Context, t Target) error {
	if e := c.execute(ctx, "systemctl", "restart", t.Service); e != nil {
		return e
	}
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	return c.execute(ctx, "systemctl", "is-active", "--quiet", t.Service)
}

// Run records a receipt before side effects. An interrupted operation is never
// automatically replayed. A new explicit task is needed after inspection.
func (c *Controller) Run(ctx context.Context, cmd Command) Result {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := Result{ID: cmd.ID}
	fail := func(message string) Result { result.Error = message; return result }
	if e := Validate(cmd); e != nil {
		return fail(e.Error())
	}
	t, ok := c.Targets[cmd.Target]
	if !ok {
		return fail("此服务未在 Agent 本机授权")
	}
	if cmd.Expires < time.Now().Unix() || cmd.Expires > time.Now().Add(10*time.Minute).Unix() {
		return fail("任务已过期或有效期无效")
	}
	if e := os.MkdirAll(c.StateDir, 0700); e != nil {
		return fail("任务状态目录不可写")
	}
	if e := os.Chmod(c.StateDir, 0700); e != nil {
		return fail("任务状态权限设置失败")
	}
	unlock, e := lockDirectory(c.StateDir)
	if e != nil {
		return fail("另一个 Agent 进程正在执行管理任务")
	}
	defer unlock()
	receipt := filepath.Join(c.StateDir, cmd.ID+".json")
	if b, e := os.ReadFile(receipt); e == nil {
		var old struct {
			Hash   string
			Result Result
		}
		if json.Unmarshal(b, &old) == nil {
			raw, _ := json.Marshal(cmd)
			if old.Hash == revision(raw) {
				return old.Result
			}
		}
		return fail("任务标识冲突")
	}
	// Bounded persistent deduplication, retaining receipts beyond every valid task lifetime.
	entries, _ := os.ReadDir(c.StateDir)
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".json") {
			if info, e := entry.Info(); e == nil && time.Since(info.ModTime()) > 24*time.Hour {
				os.Remove(filepath.Join(c.StateDir, entry.Name()))
			}
		}
	}
	raw, _ := json.Marshal(cmd)
	hash := revision(raw)
	save := func(r Result) error {
		b, _ := json.Marshal(struct {
			Hash   string
			Result Result
		}{hash, r})
		return atomic(receipt, b, 0600)
	}
	interrupted := Result{ID: cmd.ID, Error: "上次执行中断；请先检查远端配置和服务状态，再创建新任务"}
	if e := save(interrupted); e != nil {
		return fail("任务回执无法保存，未执行操作")
	}
	result = c.perform(ctx, t, cmd)
	if e := save(result); e != nil {
		return Result{ID: cmd.ID, Error: "操作结果无法保存，请检查服务状态后再操作"}
	}
	return result
}
func (c *Controller) perform(parent context.Context, t Target, cmd Command) Result {
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	r := Result{ID: cmd.ID}
	fail := func(s string) Result { r.Error = s; return r }
	if cmd.Action == "status" {
		r.OK = true
		r.State = "inactive"
		if c.execute(ctx, "systemctl", "is-active", "--quiet", t.Service) == nil {
			r.State = "active"
		}
		return r
	}
	current, e := read(t.Config)
	if e != nil {
		return fail("无法读取目标配置")
	}
	r.Revision = revision(current)
	if cmd.Action == "read" {
		r.OK = true
		r.Content = string(current)
		return r
	}
	if cmd.Action == "start" || cmd.Action == "stop" || cmd.Action == "reload" {
		if !t.Writable {
			return fail("本机未授权修改此服务")
		}
		if cmd.Action != "stop" && c.validate(ctx, t, t.Config) != nil {
			return fail("现有配置检查失败，未操作服务")
		}
		if c.execute(ctx, "systemctl", cmd.Action, t.Service) != nil {
			return fail("服务操作失败，请检查远端日志")
		}
		active := c.execute(ctx, "systemctl", "is-active", "--quiet", t.Service) == nil
		if cmd.Action == "stop" && active || cmd.Action != "stop" && !active {
			return fail("服务状态未达到预期")
		}
		r.OK = true
		r.State = "inactive"
		if active {
			r.State = "active"
		}
		return r
	}
	if cmd.Action == "restart" {
		if !t.Writable {
			return fail("本机未授权修改此服务")
		}
		if c.validate(ctx, t, t.Config) != nil {
			return fail("现有配置检查失败，未重启")
		}
		if c.healthy(ctx, t) != nil {
			return fail("服务未通过启动检查")
		}
		r.OK = true
		r.State = "active"
		return r
	}
	if cmd.Action == "validate" && !t.Writable {
		return fail("本机未授权校验自定义配置")
	}
	if cmd.Action == "apply" || cmd.Action == "rollback" {
		if !t.Writable {
			return fail("本机未授权修改此服务")
		}
		if cmd.Revision != r.Revision {
			return fail("配置已被其他操作修改，请重新读取")
		}
	}
	content := []byte(cmd.Content)
	backup := filepath.Join(c.StateDir, cmd.Target+".backup")
	if cmd.Action == "rollback" {
		content, e = read(backup)
		if e != nil {
			return fail("没有可恢复的配置备份")
		}
	}
	if len(content) == 0 {
		return fail("配置内容不能为空")
	}
	if t.Kind != "nginx" {
		var doc map[string]any
		if json.Unmarshal(content, &doc) != nil || doc == nil {
			return fail("配置必须为 JSON 对象")
		}
	}
	info, e := regular(t.Config)
	if e != nil {
		return fail("目标配置类型无效")
	}
	f, e := os.CreateTemp(filepath.Dir(t.Config), ".mx-check-*.json")
	if e != nil {
		return fail("无法创建配置检查文件")
	}
	candidate := f.Name()
	defer os.Remove(candidate)
	if _, e = f.Write(content); e != nil {
		f.Close()
		return fail("配置写入失败")
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return fail("配置同步失败")
	}
	f.Close()
	if c.validate(ctx, t, candidate) != nil {
		return fail("配置未通过内核检查，未替换生效配置")
	}
	if cmd.Action == "validate" {
		r.OK = true
		return r
	}
	latest, e := read(t.Config)
	if e != nil || revision(latest) != r.Revision {
		return fail("检查期间配置已变化，未写入")
	}
	if e = atomic(backup, current, 0600); e != nil {
		return fail("备份失败，未替换配置")
	}
	// Preserve mode and owner; the target may run as an unprivileged service user.
	if e = preserveOwner(candidate, info); e != nil {
		return fail("无法保留配置所有者")
	}
	if e = os.Chmod(candidate, info.Mode().Perm()); e != nil {
		return fail("配置权限设置失败")
	}
	if e = os.Rename(candidate, t.Config); e != nil {
		return fail("配置替换失败")
	}
	if c.healthy(ctx, t) != nil {
		rollbackCtx, stop := context.WithTimeout(context.Background(), 30*time.Second)
		defer stop()
		if e = restore(t.Config, current, info); e != nil {
			return fail("服务启动失败且配置恢复失败，请立即检查远端")
		}
		if c.healthy(rollbackCtx, t) != nil {
			return fail("已恢复旧配置，但服务未恢复，请检查远端日志")
		}
		r.Revision = revision(current)
		return fail("新配置启动失败，已恢复旧配置和服务")
	}
	r.OK = true
	r.Revision = revision(content)
	r.State = "active"
	return r
}
func (c *Controller) Capabilities() []string {
	keys := []string{}
	for k := range c.Targets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
func restore(path string, b []byte, info os.FileInfo) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".mx-restore-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if _, e = f.Write(b); e != nil {
		f.Close()
		return e
	}
	if e = f.Sync(); e != nil {
		f.Close()
		return e
	}
	f.Close()
	if e = preserveOwner(name, info); e != nil {
		return e
	}
	if e = os.Chmod(name, info.Mode().Perm()); e != nil {
		return e
	}
	return os.Rename(name, path)
}
