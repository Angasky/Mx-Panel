package releaseupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/Angasky/dingzhi-ban/deploy"
)

func (m *Manager) StartUninstall(ctx context.Context, current string) (*Job, error) {
	return m.StartUninstallWithData(ctx, current, false)
}
func (m *Manager) StartUninstallWithData(ctx context.Context, current string, purge bool) (*Job, error) {
	if m == nil || !ValidVersion(current) {
		return nil, errors.New("仅标准 Go 安装支持面板卸载")
	}
	job, err := m.queueRemovalOption(current, "uninstall", purge)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 12*time.Second)
	defer cancel()
	if err := m.launch(ctx, *job); err != nil {
		return nil, errors.New("卸载任务启动待核对，请查看维护状态")
	}
	return job, nil
}

func (m *Manager) claimUninstall(current, id string) (*Job, error) {
	unlock, err := lockStatus(m.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	job, err := m.Status()
	if err != nil || job == nil || job.Operation != "uninstall" || job.Version != current || job.ID != id || job.Status != "queued" || !ValidVersion(current) {
		return nil, errors.New("卸载任务不存在、已过期或版本不匹配")
	}
	job.Status, job.Stage = "running", "uninstall"
	return job, m.save(*job)
}

func (m *Manager) RunUninstall(current, id string) error {
	job, err := m.claimUninstall(current, id)
	if err != nil {
		return err
	}
	// Allow the HTTP acceptance response to leave the old service first.
	time.Sleep(2 * time.Second)
	err = m.removeService(job.PurgeData)
	job.Status, job.Stage = "succeeded", "complete"
	if err != nil {
		job.Status, job.Error = "failed", err.Error()
	}
	return errors.Join(err, m.save(*job))
}

func (m *Manager) removeService(purge bool) error {
	old, err := os.Readlink(base + "/current")
	if err != nil || filepath.Dir(old) != base+"/releases" {
		return errors.New("当前安装路径核对失败")
	}
	self, err := os.Stat("/proc/self/exe")
	installed, otherErr := os.Stat(filepath.Join(old, "mxioc"))
	if err != nil || otherErr != nil || !os.SameFile(self, installed) {
		return errors.New("卸载工作进程与安装版本不匹配")
	}
	dir, err := os.MkdirTemp(base, ".uninstall-*")
	if err != nil {
		return errors.New("卸载暂存目录创建失败")
	}
	defer os.RemoveAll(dir)
	script := filepath.Join(dir, "install-go.sh")
	if err := os.WriteFile(script, []byte(deploy.Installer), 0600); err != nil {
		return errors.New("卸载脚本准备失败")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, "bash", script, "uninstall")
	command.Env = append(os.Environ(), "MXIOC_GO_EXPECT_CURRENT="+old, "MXIOC_GO_PURGE_DATA=0")
	if purge {
		command.Env = append(command.Env, "MXIOC_GO_PURGE_DATA=1")
	}
	if err := command.Run(); err != nil {
		if purge {
			return errors.New("卸载或清空数据未完全确认，请检查服务与数据路径；可能已删除部分数据")
		}
		return errors.New("服务卸载未确认，请检查 systemd 状态；数据未主动删除")
	}
	return nil
}
