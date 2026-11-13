package remote

import (
	"context"
	"errors"
	"strings"
	"time"
)

// Verify the running service uses exactly the configuration our writer manages.
// This does not install, restart, or rewrite the remote service.
func validateCoreAttachment(kind, command string) error {
	path, err := corePath(kind)
	if err != nil {
		return err
	}
	args := strings.Split(strings.TrimSpace(command), "\n")
	count := 0
	for i := 1; i < len(args); i++ {
		switch args[i] {
		case "-c", "-config", "--config":
			i++
			if i >= len(args) || args[i] != path {
				return errors.New("运行服务使用非标准配置路径，暂不支持接管")
			}
			count++
		case "-C", "--config-directory", "-confdir":
			return errors.New("运行服务使用多文件配置目录，暂不支持直接接管，请保留原配置")
		default:
			if strings.HasPrefix(args[i], "-") && strings.Contains(args[i], "=") {
				return errors.New("暂不支持此内核启动参数，请保留原配置")
			}
		}
	}
	if count != 1 {
		return errors.New("无法确认运行服务使用标准单文件配置，未接管")
	}
	return nil
}

func (m *Manager) attachCore(ctx context.Context, id string) (Record, error) {
	return m.withCore(ctx, id, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
		binary := "/usr/local/bin/xray"
		check := "run -test -config"
		if kind == "sing-box" {
			binary = "/usr/bin/sing-box"
			check = "check -c"
		}
		command, err := run(ctx, `set -eu
systemctl is-active --quiet `+kind+`
pid=$(systemctl show --property=MainPID --value `+kind+`)
case "$pid" in ''|0|*[!0-9]*) exit 1;; esac
test "$(readlink -f /proc/$pid/exe)" = "$(readlink -f `+binary+`)"
tr '\000' '\n' < /proc/$pid/cmdline
`, 64<<10)
		if err != nil {
			return nil, errors.New("未找到使用标准内核程序的运行中 systemd 服务；容器或第三方面板请接入原面板")
		}
		if err = validateCoreAttachment(kind, command); err != nil {
			return nil, err
		}
		if _, _, err = readCore(ctx, kind, run); err != nil {
			return nil, err
		}
		path, _ := corePath(kind)
		if _, err = run(ctx, binary+" "+check+" "+quote(path)+" >/dev/null 2>&1", 64<<10); err != nil {
			return nil, errors.New("现有内核配置校验失败，未接管或修改配置")
		}
		if err = m.updateDerived(id, Record{"existingVerifiedAt": time.Now().Unix(), "lastError": ""}); err != nil {
			return nil, err
		}
		record["existingVerifiedAt"] = time.Now().Unix()
		return Record{"server": publicServer(record), "message": "已有独立内核验证成功，未安装、重启或修改远端配置"}, nil
	})
}
