package releaseupdate

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

const (
	Repository = "Angasky/Mx-Panel"
	base       = "/opt/mxioc-go"
	executable = base + "/current/mxioc"
)

var (
	versionPattern = regexp.MustCompile(`^v(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$`)
	ErrBusy        = errors.New("已有 Go 更新任务正在运行")
)

func ValidVersion(v string) bool { return versionPattern.MatchString(v) }

func Newer(target, current string) bool {
	return ValidVersion(target) && ValidVersion(current) &&
		version.Compare("go"+target[1:], "go"+current[1:]) > 0
}

type Job struct {
	PurgeData bool   `json:"purgeData,omitempty"`
	Operation string `json:"operation,omitempty"`
	ID        string `json:"id"`
	Version   string `json:"version"`
	Status    string `json:"status"`
	Stage     string `json:"stage"`
	Started   int64  `json:"startedAt"`
	Error     string `json:"error,omitempty"`
}

type Manager struct {
	path   string
	launch func(context.Context, Job) error
}

// Managed only enables the web action for the standard packaged Linux service.
func Managed() *Manager {
	if runtime.GOOS != "linux" || (runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64") || os.Geteuid() != 0 {
		return nil
	}
	self, err := os.Executable()
	if err != nil {
		return nil
	}
	a, err := os.Stat(self)
	b, otherErr := os.Stat(executable)
	if err != nil || otherErr != nil || !os.SameFile(a, b) {
		return nil
	}
	systemd, err := exec.LookPath("systemd-run")
	if err != nil {
		return nil
	}
	return &Manager{path: base + "/update-status.json", launch: func(ctx context.Context, job Job) error {
		action, target := "--apply-release", job.Version
		if job.Operation == "uninstall" {
			action, target = "--remove-service", "true"
		}
		return exec.CommandContext(ctx, systemd, "--quiet", "--collect", "--unit=mxioc-go-update.service",
			"--property=Type=exec", "--property=RuntimeMaxSec=10min", "--property=TimeoutStopSec=45s",
			executable, action+"="+target, "--update-job", job.ID).Run()
	}}
}

func (m *Manager) read() (*Job, error) {
	data, err := os.ReadFile(m.path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var job Job
	if err := json.Unmarshal(data, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

func (m *Manager) Status() (*Job, error) {
	job, err := m.read()
	if err != nil || job == nil {
		return job, err
	}
	age := time.Since(time.Unix(job.Started, 0))
	if (job.Status == "queued" && age > time.Minute) || (job.Status == "running" && age > 12*time.Minute) {
		job.Status, job.Error = "interrupted", "更新任务未返回结果，请核对当前运行版本和服务状态"
	}
	return job, nil
}

func (m *Manager) Start(ctx context.Context, current, target string) (*Job, error) {
	if !Newer(target, current) {
		return nil, errors.New("只能更新到已检查的较新版本")
	}
	job, err := m.queue(target)
	if err != nil {
		return nil, err
	}
	// The request may disconnect after systemd accepts the job. Its status
	// remains available and the queue entry expires if the worker never starts.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
	defer cancel()
	if err := m.launch(ctx, *job); err != nil {
		return nil, errors.New("更新任务启动待核对，请刷新维护页查看状态")
	}
	return job, nil
}

func (m *Manager) queue(target string) (*Job, error) { return m.queueOperation(target, "") }

func (m *Manager) queueOperation(target, operation string) (*Job, error) {
	return m.queueRemovalOption(target, operation, false)
}
func (m *Manager) queueRemovalOption(target, operation string, purge bool) (*Job, error) {
	unlock, err := lockStatus(m.path)
	if err != nil {
		return nil, errors.New("更新任务状态锁定失败")
	}
	defer unlock()
	previous, err := m.Status()
	if err != nil {
		return nil, errors.New("更新任务状态读取失败")
	}
	if previous != nil && (previous.Status == "running" || previous.Status == "queued") {
		return nil, ErrBusy
	}
	id := make([]byte, 16)
	if _, err := rand.Read(id); err != nil {
		return nil, errors.New("更新任务标识生成失败")
	}
	job := Job{PurgeData: purge, Operation: operation, ID: hex.EncodeToString(id), Version: target, Status: "queued", Stage: "queued", Started: time.Now().Unix()}
	if err := m.save(job); err != nil {
		return nil, errors.New("更新任务保存失败")
	}
	return &job, nil
}

func (m *Manager) save(job Job) error {
	tmp, err := os.CreateTemp(filepath.Dir(m.path), ".update-status-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()
	if err := json.NewEncoder(tmp).Encode(job); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), m.path)
}
