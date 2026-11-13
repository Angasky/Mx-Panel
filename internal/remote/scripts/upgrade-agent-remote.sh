set -euo pipefail
umask 077
[[ $(id -u) == 0 ]] || exit 1
for dep in curl tar sha256sum flock systemctl install; do command -v "$dep" >/dev/null || exit 1; done
exec 9>/run/mxioc-agent-install.lock
flock -n 9 || exit 1
for path in /etc/mxioc-agent.json /usr/local/bin/mxioc-agent /etc/systemd/system/mxioc-agent.service; do
 [[ -f "$path" && ! -L "$path" ]] || { echo '仅支持已安装的标准 Agent 普通文件'; exit 1; }
done
systemctl is-active --quiet mxioc-agent.service || { echo 'Agent 未运行，拒绝自动升级'; exit 1; }
# Custom unit paths must not be silently upgraded through the standard binary.
[[ $(systemctl show mxioc-agent.service -p FragmentPath --value) == /etc/systemd/system/mxioc-agent.service ]] || exit 1
[[ $(systemctl show mxioc-agent.service -p ExecStart --value) == *'/usr/local/bin/mxioc-agent --config /etc/mxioc-agent.json'* ]] || exit 1
config_hash=$(sha256sum /etc/mxioc-agent.json | cut -d' ' -f1)
case "$(uname -m)" in
 x86_64) arch=amd64; digest=33326c6c309275af26049d6462de76291bbf6011fab44c17166c4b795dfc662b;;
 aarch64|arm64) arch=arm64; digest=1b7e06835970843ac2e6291c8a46099d6eca273342e529f01e517e32c1d46903;;
 *) exit 1;;
esac
stage=$(mktemp -d /var/tmp/mxioc-agent-upgrade.XXXXXX)
trap 'rm -rf -- "$stage"' EXIT
package="mxioc-agent-v0.1.32-linux-$arch.tar.gz"
printf 'MXIOC_STAGE=downloading\n'
curl -fLsS --retry 2 --connect-timeout 15 --max-time 180 --proto '=https' --proto-redir '=https' "https://github.com/Angasky/Mx-Panel/releases/download/go-v0.1.32/$package" -o "$stage/$package"
(cd "$stage" && printf '%s  %s\n' "$digest" "$package" | sha256sum -c -)
[[ $(tar -tzf "$stage/$package" | sort) == $'SHA256SUMS\ninstall-agent.sh\nmxioc-agent' ]] || exit 1
# Read only the binary from a digest-pinned release; keep local config and unit.
tar -xOf "$stage/$package" mxioc-agent > "$stage/mxioc-agent"
chmod 700 "$stage/mxioc-agent"
"$stage/mxioc-agent" --config /etc/mxioc-agent.json --check
[[ $(sha256sum /etc/mxioc-agent.json | cut -d' ' -f1) == "$config_hash" ]] || exit 1
if cmp -s "$stage/mxioc-agent" /usr/local/bin/mxioc-agent; then
 printf 'MXIOC_AGENT_INSTALLED\nMXIOC_STAGE=installed\n'; exit 0
fi
mkdir -p /var/backups
backup=$(mktemp -d /var/backups/mxioc-agent-upgrade.XXXXXXXX)
cp -p /usr/local/bin/mxioc-agent "$backup/mxioc-agent"
cp -p /etc/systemd/system/mxioc-agent.service "$backup/mxioc-agent.service"
cp -p /etc/mxioc-agent.json "$backup/mxioc-agent.json"
rollback() {
 trap - ERR HUP INT TERM
 set +e
 failed=false
 systemctl stop mxioc-agent.service 9>&- || failed=true
 install -m 0755 "$backup/mxioc-agent" /usr/local/bin/.mxioc-agent-rollback || failed=true
 mv -f /usr/local/bin/.mxioc-agent-rollback /usr/local/bin/mxioc-agent || failed=true
 systemctl start mxioc-agent.service 9>&- || failed=true
 systemctl is-active --quiet mxioc-agent.service || failed=true
 if $failed; then echo MXIOC_ROLLBACK_FAILED; fi
 exit 1
}
trap rollback ERR HUP INT TERM
printf 'MXIOC_STAGE=installing\n'
systemctl stop mxioc-agent.service 9>&-
install -m 0755 "$stage/mxioc-agent" /usr/local/bin/.mxioc-agent-upgrade
mv -f /usr/local/bin/.mxioc-agent-upgrade /usr/local/bin/mxioc-agent
systemctl start mxioc-agent.service 9>&-
sleep 2
systemctl is-active --quiet mxioc-agent.service
[[ $(sha256sum /etc/mxioc-agent.json | cut -d' ' -f1) == "$config_hash" ]]
trap - ERR HUP INT TERM
printf 'MXIOC_AGENT_INSTALLED\nMXIOC_STAGE=installed\n'
