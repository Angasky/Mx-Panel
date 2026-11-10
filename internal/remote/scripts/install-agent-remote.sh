set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || { echo '需要 root 权限'; exit 1; }
for dependency in curl tar sha256sum base64 flock systemctl; do command -v "$dependency" >/dev/null || { echo "缺少依赖 $dependency"; exit 1; }; done
exec 9>/run/mxioc-agent-install.lock
flock -n 9 || { echo '已有 Agent 安装正在执行'; exit 1; }
case "$(uname -m)" in
 x86_64) arch=amd64; digest=a9817eb723bffe743972f309977f84c7c33ddbd3c36b0845f8d2b6f10459fd6a;;
 aarch64|arm64) arch=arm64; digest=c9836609d9d73b537695b3d9c2786d26106a0fb0ee5067537c6da34521f3a8d3;;
 *) echo '不支持的架构'; exit 1;;
esac
stage=$(mktemp -d /var/tmp/mxioc-agent-install.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
printf 'MXIOC_STAGE=downloading\n'
package="mxioc-agent-v0.1.15-linux-$arch.tar.gz"
curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 --proto '=https' "https://github.com/Angasky/Mx-Panel/releases/download/go-v0.1.15/$package" -o "$stage/$package"
(cd "$stage" && printf '%s  %s\n' "$digest" "$package" | sha256sum -c -)
[[ $(tar -tzf "$stage/$package" | sort) == $'SHA256SUMS\ninstall-agent.sh\nmxioc-agent' ]] || { echo '发布包文件列表异常'; exit 1; }
mkdir "$stage/bundle"
tar -xzf "$stage/$package" -C "$stage/bundle" --no-same-owner
for item in mxioc-agent install-agent.sh SHA256SUMS; do [[ -f "$stage/bundle/$item" && ! -L "$stage/bundle/$item" ]] || exit 1; done
(cd "$stage/bundle" && sha256sum -c SHA256SUMS)
printf '%s' '__CONFIG64__' | base64 -d > "$stage/config.json"
chmod 600 "$stage/config.json"
"$stage/bundle/mxioc-agent" --config "$stage/config.json" --check
# Reject symlink destinations before backup or replacement.
for path in /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
 [[ ! -L "$path" ]] || { echo '安装目标不能是符号链接'; exit 1; }
 [[ ! -e "$path" || -f "$path" ]] || { echo '安装目标必须是普通文件'; exit 1; }
done
was_active=false; was_enabled=false
systemctl is-active --quiet mxioc-agent.service && was_active=true
systemctl is-enabled --quiet mxioc-agent.service && was_enabled=true
mkdir "$stage/backup"
for path in /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
 [[ ! -f "$path" ]] || cp -p "$path" "$stage/backup/$(basename "$path")"
done
rollback() {
 trap - ERR HUP INT TERM
 set +e
 failed=false
 systemctl stop mxioc-agent.service >/dev/null 2>&1
 for path in /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
  if [[ -f "$stage/backup/$(basename "$path")" ]]; then cp -p "$stage/backup/$(basename "$path")" "$path" || failed=true
  else rm -f "$path" || failed=true; fi
 done
 systemctl daemon-reload || failed=true
 if $was_enabled; then systemctl enable mxioc-agent.service >/dev/null 2>&1 || failed=true
 else systemctl disable mxioc-agent.service >/dev/null 2>&1; fi
 if $was_active; then systemctl start mxioc-agent.service || failed=true; fi
 if $failed; then trap - EXIT; echo 'MXIOC_ROLLBACK_FAILED'; echo "恢复备份保留在 $stage/backup"; else echo '已恢复安装前的 Agent 配置和服务文件'; fi
 exit 1
}
trap rollback ERR HUP INT TERM
printf 'MXIOC_STAGE=installing\n'
install -m 0600 "$stage/config.json" /etc/mxioc-agent.json
bash "$stage/bundle/install-agent.sh"
systemctl is-active --quiet mxioc-agent.service
trap - ERR HUP INT TERM
printf 'MXIOC_AGENT_INSTALLED\nMXIOC_STAGE=installed\n'
