package web

import (
	"context"
	"errors"
	"github.com/Angasky/dingzhi-ban/internal/netguard"
	"github.com/Angasky/dingzhi-ban/internal/remote"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

func probeBootstrap(public string, port int) string {
	return probeBootstrapOptions(public, port, false)
}
func probeBootstrapOptions(public string, port int, repair bool) string {
	fix := "0"
	if repair {
		fix = "1"
	}
	return `set -eu
if [ "$(id -u)" = 0 ]; then mx_runner=sh; else
 command -v sudo >/dev/null 2>&1 && sudo -n true >/dev/null 2>&1 || { echo MX_SYNC_ERROR=NEED_ROOT_OR_SUDO; exit 1; }
 mx_runner='sudo -n sh'
fi
$mx_runner <<'MX_PANEL_ACCESS_SCRIPT'
set -eu
fail() { printf 'MX_SYNC_ERROR=%s\n' "$1"; exit 1; }
for dep in ssh-keygen flock; do command -v "$dep" >/dev/null 2>&1 || fail "MISSING_$dep"; done
sshd_bin=$(command -v sshd || true)
[ -n "$sshd_bin" ] || sshd_bin=/usr/sbin/sshd
[ -x "$sshd_bin" ] || fail SSHD_MISSING
"$sshd_bin" -t 2>/dev/null || fail SSHD_CONFIG_INVALID
settings=$("$sshd_bin" -T) || fail SSHD_CONFIG_INVALID
printf '%s\n' "$settings" | grep -Eq '^permitrootlogin (yes|without-password|prohibit-password)$' || fail ROOT_LOGIN_DISABLED
printf '%s\n' "$settings" | grep -E '^authorizedkeysfile ' | grep -Eq '(^| )(\.ssh/authorized_keys|/root/\.ssh/authorized_keys)( |$)' || fail CUSTOM_KEY_PATH
if ! printf '%s\n' "$settings" | grep -Eq '^pubkeyauthentication yes$'; then
 [ '` + fix + `' = 1 ] || fail PUBKEY_DISABLED
 [ -f /etc/ssh/sshd_config ] && [ ! -L /etc/ssh/sshd_config ] || fail CUSTOM_SSH_CONFIG
 command -v systemctl >/dev/null 2>&1 || fail REPAIR_NEEDS_SYSTEMD
 svc=''
 for candidate in ssh.service sshd.service; do if systemctl is-active --quiet "$candidate"; then svc=$candidate; break; fi; done
 [ -n "$svc" ] || fail SSH_SERVICE_NOT_FOUND
 exec 8>/run/mx-panel-ssh-config.lock
 flock -w 10 8 || fail KEY_LOCK_BUSY
mkdir -p /var/backups/mx-panel-ssh
 chmod 700 /var/backups/mx-panel-ssh
 backup=$(mktemp /var/backups/mx-panel-ssh/sshd_config.XXXXXXXX)
 cp -p /etc/ssh/sshd_config "$backup"
 temporary=$(mktemp /etc/ssh/.mx-panel-sshd.XXXXXXXX)
 trap 'rm -f "$temporary"' EXIT HUP INT TERM
 { printf '# Mx-Panel explicitly authorized public-key login\nPubkeyAuthentication yes\n'; cat "$backup"; } > "$temporary"
 chmod --reference="$backup" "$temporary"
 chown --reference="$backup" "$temporary"
 "$sshd_bin" -t -f "$temporary" 2>/dev/null || fail REPAIR_CONFIG_INVALID
 mv "$temporary" /etc/ssh/sshd_config
 if ! "$sshd_bin" -T | grep -Eq '^pubkeyauthentication yes$'; then cp -p "$backup" /etc/ssh/sshd_config; fail PUBKEY_OVERRIDE_REJECTED; fi
 if ! systemctl reload "$svc"; then cp -p "$backup" /etc/ssh/sshd_config; systemctl reload "$svc" || true; fail RELOAD_FAILED_RESTORED; fi
 printf 'MX_SYNC_REPAIR=PUBKEY_ENABLED\n'
fi
[ ! -L /root/.ssh ] && [ ! -L /root/.ssh/authorized_keys ] || fail KEY_PATH_SYMLINK
[ ! -e /root/.ssh/authorized_keys ] || [ -f /root/.ssh/authorized_keys ] || fail KEY_PATH_INVALID
mkdir -p /root/.ssh
chmod 700 /root/.ssh
exec 9>/root/.ssh/mx-panel-sync.lock
flock -w 10 9 || fail KEY_LOCK_BUSY
key='` + strings.TrimSpace(public) + ` mx-panel-probe-sync'
touch /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
grep -qxF "$key" /root/.ssh/authorized_keys || printf '\n%s\n' "$key" >> /root/.ssh/authorized_keys
for file in /etc/ssh/ssh_host_*_key.pub; do
 [ -f "$file" ] || continue
 ssh-keygen -lf "$file" -E sha256 | awk '{print "MX_SYNC_FP=" $2}'
done
printf '%s\n' "$settings" | awk '$1=="port" {print "MX_SYNC_PORT=" $2}'
printf 'MX_SYNC_READY\n'
MX_PANEL_ACCESS_SCRIPT
`
}
func probeFailureReason(output string) string {
	reasons := map[string]string{"NEED_ROOT_OR_SUDO": "Agent 需要 root 或免密码 sudo 权限", "PUBKEY_DISABLED": "SSH 已关闭公钥登录；可选择“启用公钥登录并重试”，保留密码登录并备份 SSH 配置", "ROOT_LOGIN_DISABLED": "SSH 禁止 root 登录；未自动放宽此策略，请核对服务器登录配置", "SSHD_MISSING": "服务器未安装 OpenSSH sshd", "SSHD_CONFIG_INVALID": "sshd 配置校验失败，请先修复原服务器 SSH 配置", "CUSTOM_KEY_PATH": "服务器使用自定义 AuthorizedKeysFile，未擅自修改", "KEY_PATH_SYMLINK": "SSH 授权目录或文件为符号链接，已停止写入", "REPAIR_NEEDS_SYSTEMD": "自动开启公钥登录目前需要 systemd", "SSH_SERVICE_NOT_FOUND": "未找到运行中的 ssh/sshd 服务", "RELOAD_FAILED_RESTORED": "SSH 重载失败，已恢复原配置，请检查服务", "PUBKEY_OVERRIDE_REJECTED": "公钥设置受其他 SSH 配置覆盖，已恢复原配置"}
	for _, line := range strings.Split(output, "\n") {
		code := strings.TrimPrefix(strings.TrimSpace(line), "MX_SYNC_ERROR=")
		if msg, ok := reasons[code]; ok {
			return msg
		}
		if strings.HasPrefix(code, "MISSING_") {
			return "服务器缺少命令：" + strings.TrimPrefix(code, "MISSING_")
		}
	}
	if strings.Contains(output, "Agent must run as root") {
		return "旧授权脚本要求 root；新版可使用 Agent 的免密码 sudo，请重试"
	}
	return "旧授权任务失败且未记录具体原因；请使用新版重试以获取准确诊断（常见为公钥登录关闭或端口不符）"
}
func (s *Server) probeVerifiedConnection(ctx context.Context, cfg probeSyncConfig, b probeBinding, private, output string) (remote.Connection, error) {
	hosts := []string{b.Host}
	var clients []probeClient
	if s.probeRequest(ctx, cfg, "GET", "/api/admin/client/list", nil, &clients) == nil {
		for _, c := range clients {
			if c.UUID == b.UUID {
				for _, raw := range []string{c.IPv4, c.IPv6} {
					ip, e := netip.ParseAddr(strings.TrimSpace(raw))
					if e == nil && netguard.PublicAddress(ip) && ip.String() != b.Host {
						hosts = append(hosts, ip.String())
					}
				}
			}
		}
	}
	ports := []int{b.Port}
	fingerprints := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "MX_SYNC_FP=") {
			fingerprints[strings.TrimPrefix(line, "MX_SYNC_FP=")] = true
		}
		if strings.HasPrefix(line, "MX_SYNC_PORT=") {
			port, e := strconv.Atoi(strings.TrimPrefix(line, "MX_SYNC_PORT="))
			if e == nil && port > 0 && port <= 65535 && port != b.Port && len(ports) < 8 {
				ports = append(ports, port)
			}
		}
	}
	authFailed, pinMismatch := false, false
	for _, port := range ports {
		for _, host := range hosts {
			conn := remote.Connection{Host: host, Port: port, User: "root", PrivateKey: private}
			attempt, cancel := context.WithTimeout(ctx, 4*time.Second)
			fp, e := remote.Probe(attempt, conn)
			cancel()
			if e != nil {
				continue
			}
			if !fingerprints[fp] {
				pinMismatch = true
				continue
			}
			conn.Fingerprint = fp
			attempt, cancel = context.WithTimeout(ctx, 8*time.Second)
			client, e := remote.Connect(attempt, conn)
			cancel()
			if e != nil {
				authFailed = true
				continue
			}
			client.Close()
			return conn, nil
		}
	}
	if pinMismatch {
		return remote.Connection{}, errors.New("可达 SSH 的主机指纹与原探针不一致；可能为共享 NAT 地址或端口映射，未授权连接")
	}
	if authFailed {
		return remote.Connection{}, errors.New("SSH 可达但密钥登录失败；请检查 Match、AllowUsers、root 登录策略或云镜像的登录限制")
	}
	return remote.Connection{}, errors.New("已授权，但探针提供的 IPv4/IPv6 和 SSH 端口均无法连通；请填写公网映射地址/端口或检查防火墙")
}
