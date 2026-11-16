package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/coreapi"
)

const coreAPIPermission = "/etc/mxioc-agent-xray-api"

type coreTask struct {
	ID      string       `json:"id"`
	Expires int64        `json:"expires"`
	Plan    coreapi.Plan `json:"plan"`
}
type coreResult struct {
	ID     string `json:"id"`
	Output string `json:"output"`
	Error  string `json:"error,omitempty"`
}

func coreAPIAllowed() bool { return coreAPIAllowedAt(coreAPIPermission) }
func coreAPIAllowedAt(path string) bool {
	info, e := os.Lstat(path)
	if e != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == 0 && os.Geteuid() == 0
}

type boundedCoreOutput struct {
	bytes.Buffer
	limit    int
	overflow bool
}

func (b *boundedCoreOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := b.limit - b.Len()
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	b.Buffer.Write(p)
	return n, nil
}
func runCoreTask(ctx context.Context, dir string, task coreTask) coreResult {
	return runCoreTaskAt(ctx, dir, task, coreAPIPermission)
}
func runCoreTaskAt(ctx context.Context, dir string, task coreTask, permission string) coreResult {
	r := coreResult{ID: task.ID}
	fail := func(s string) coreResult { r.Error = s; return r }
	id, e := hex.DecodeString(task.ID)
	if e != nil || len(id) != 16 || len(task.ID) != 32 || task.Expires < time.Now().Unix() || task.Expires > time.Now().Add(3*time.Minute).Unix() {
		return fail("任务身份或有效期无效")
	}
	if !coreAPIAllowedAt(permission) {
		return fail("本机未授权 Xray 节点 API")
	}
	if e = os.MkdirAll(dir, 0700); e != nil {
		return fail("无法创建任务目录")
	}
	lock, e := os.OpenFile(filepath.Join(filepath.Dir(dir), "operation.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return fail("无法锁定任务")
	}
	defer lock.Close()
	if e = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); e != nil {
		return fail("已有本机节点任务执行中")
	}
	defer syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
	raw, _ := json.Marshal(task)
	sum := sha256.Sum256(raw)
	hash := hex.EncodeToString(sum[:])
	receipt := filepath.Join(dir, task.ID+".json")
	var saved struct {
		Hash   string
		Result coreResult
	}
	if b, e := os.ReadFile(receipt); e == nil {
		if json.Unmarshal(b, &saved) == nil && saved.Hash == hash {
			return saved.Result
		}
		return fail("任务标识冲突")
	} else if !os.IsNotExist(e) {
		return fail("任务回执读取失败")
	}
	save := func(result coreResult) error {
		b, e := json.Marshal(struct {
			Hash   string
			Result coreResult
		}{hash, result})
		if e != nil {
			return e
		}
		f, e := os.CreateTemp(dir, ".receipt-")
		if e != nil {
			return e
		}
		defer os.Remove(f.Name())
		defer f.Close()
		if _, e = f.Write(b); e != nil {
			return e
		}
		if e = f.Sync(); e != nil {
			return e
		}
		if e = f.Close(); e != nil {
			return e
		}
		return os.Rename(f.Name(), receipt)
	}
	if e = save(fail("上次执行结果不明，请读取配置核对；未重复执行")); e != nil {
		return fail("无法保存执行回执")
	}
	ctx, cancel := context.WithTimeout(ctx, 85*time.Second)
	defer cancel()
	output, e := coreapi.Execute(ctx, task.Plan, func(ctx context.Context, script string, limit int) (string, error) {
		cmd := exec.CommandContext(ctx, "/bin/bash", "-c", script)
		// Fixed scripts are generated inside ExecuteCoreRPC; never execute raw peer text.
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = 2 * time.Second
		out := &boundedCoreOutput{limit: limit}
		cmd.Stdout = out
		cmd.Stderr = out
		err := cmd.Run()
		if out.overflow {
			return "", errors.New("内核 API 输出超过限制")
		}
		return out.String(), err
	})
	r = coreResult{ID: task.ID, Output: output}
	if e != nil {
		r.Error = "本机内核操作失败：" + e.Error()
	}
	if len(r.Error) > 4096 {
		r.Error = "本机内核操作失败"
	}
	if e = save(r); e != nil {
		return fail("结果保存失败，请核对配置")
	}
	// Receipts exceed every task lifetime before removal.
	entries, _ := os.ReadDir(dir)
	for _, item := range entries {
		if strings.HasSuffix(item.Name(), ".json") {
			if info, e := item.Info(); e == nil && time.Since(info.ModTime()) > 24*time.Hour {
				os.Remove(filepath.Join(dir, item.Name()))
			}
		}
	}
	return r
}
func serveCoreAPI(ctx context.Context, c configuration) {
	endpoint, e := url.Parse(c.URL)
	if e != nil {
		return
	}
	endpoint.Path = strings.Replace(endpoint.Path, "/sub/agent/", "/sub/agent-core/", 1)
	client := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("不跟随重定向") }}
	pause := func() bool {
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return false
		case <-timer.C:
			return true
		}
	}
	for ctx.Err() == nil {
		if !coreAPIAllowed() {
			if !pause() {
				return
			}
			continue
		}
		req, e := http.NewRequestWithContext(ctx, "GET", endpoint.String(), nil)
		if e != nil {
			return
		}
		req.Header.Set("Authorization", "Bearer "+c.Token)
		response, e := client.Do(req)
		if e != nil {
			if !pause() {
				return
			}
			continue
		}
		if response.StatusCode == 204 {
			response.Body.Close()
			continue
		}
		var task coreTask
		decoder := json.NewDecoder(io.LimitReader(response.Body, 7<<20))
		decoder.UseNumber()
		decoder.DisallowUnknownFields()
		valid := response.StatusCode == 200 && decoder.Decode(&task) == nil && decoder.Decode(new(any)) == io.EOF
		response.Body.Close()
		if !valid {
			if !pause() {
				return
			}
			continue
		}
		result := runCoreTask(ctx, filepath.Join(c.StateDir, "core-api"), task)
		raw, _ := json.Marshal(result)
		for attempt := 0; attempt < 3 && ctx.Err() == nil; attempt++ {
			req, e = http.NewRequestWithContext(ctx, "POST", endpoint.String(), bytes.NewReader(raw))
			if e != nil {
				break
			}
			req.Header.Set("Authorization", "Bearer "+c.Token)
			req.Header.Set("Content-Type", "application/json")
			response, e = client.Do(req)
			if e == nil {
				response.Body.Close()
				if response.StatusCode == 200 || response.StatusCode == 409 || response.StatusCode == 403 {
					break
				}
			}
			if !pause() {
				return
			}
		}
	}
}
