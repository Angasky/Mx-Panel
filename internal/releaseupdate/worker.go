package releaseupdate

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/Angasky/dingzhi-ban/deploy"
)

func (m *Manager) Run(current, target, id string) error {
	job, err := m.claim(current, target, id)
	if err != nil {
		return err
	}
	setStage := func(stage string) error {
		job.Stage = stage
		return m.save(*job)
	}
	status, err := m.apply(target, setStage)
	job.Status = status
	if err != nil {
		job.Error = err.Error()
	} else {
		job.Stage = "complete"
	}
	return errors.Join(err, m.save(*job))
}

func (m *Manager) claim(current, target, id string) (*Job, error) {
	unlock, err := lockStatus(m.path)
	if err != nil {
		return nil, err
	}
	defer unlock()
	job, err := m.Status()
	if err != nil || job == nil || job.Status != "queued" || job.ID != id || job.Version != target || job.Operation != "" || !Newer(target, current) {
		return nil, errors.New("更新任务不存在、已过期或与当前版本不匹配")
	}
	job.Status, job.Stage = "running", "download"
	return job, m.save(*job)
}

func (m *Manager) apply(target string, stage func(string) error) (string, error) {
	old, err := os.Readlink(base + "/current")
	if err != nil || filepath.Dir(old) != base+"/releases" {
		return "failed", errors.New("当前安装路径核对失败")
	}
	self, err := os.Stat("/proc/self/exe")
	installed, installedErr := os.Stat(filepath.Join(old, "mxioc"))
	if err != nil || installedErr != nil || !os.SameFile(self, installed) {
		return "failed", errors.New("当前安装路径核对失败")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	client := releaseClient()
	dirURL := assetBase + target + "/"
	archiveName := "mxioc-go-" + target + "-linux-" + runtime.GOARCH + ".tar.gz"
	manifest, err := download(ctx, client, dirURL+"SHA256SUMS", 16<<10)
	if err != nil {
		return "failed", errors.New("无法下载发布包校验清单")
	}
	data, err := download(ctx, client, dirURL+archiveName, 32<<20)
	if err != nil {
		return "failed", errors.New("无法下载当前架构的发布包")
	}
	if err := stage("verify"); err != nil {
		return "failed", errors.New("更新状态保存失败")
	}
	if err := verifyArchive(manifest, data, archiveName); err != nil {
		return "failed", err
	}
	dir, err := os.MkdirTemp(base, ".update-*")
	if err != nil {
		return "failed", errors.New("更新暂存目录创建失败")
	}
	defer os.RemoveAll(dir)
	if err := extractRelease(data, dir, target, runtime.GOARCH); err != nil {
		return "failed", errors.New("发布包内容校验失败")
	}
	script := filepath.Join(dir, "install-go.sh")
	if err := os.WriteFile(script, []byte(strings.ReplaceAll(deploy.Installer, "\r\n", "\n")), 0600); err != nil {
		return "failed", errors.New("安装脚本准备失败")
	}
	if err := stage("install"); err != nil {
		return "failed", errors.New("更新状态保存失败")
	}
	cmd := exec.Command("bash", script, "update")
	cmd.Env = append(os.Environ(), "MXIOC_GO_EXPECT_CURRENT="+old)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "\nPrevious Go release restored.\n") {
			return "rolledBack", errors.New("新版本未通过检查，已恢复旧版本")
		}
		if strings.Contains(string(output), "Previous Go release could not be restarted.") {
			return "failed", errors.New("新版本启动失败，旧版本恢复尚未确认，请检查服务")
		}
		return "failed", errors.New("更新未完成，请核对发布包、安装目录和服务状态")
	}
	return "succeeded", nil
}
