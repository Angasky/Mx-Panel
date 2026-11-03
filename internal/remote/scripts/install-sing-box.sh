set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\n'
trap 'rc=$?; printf "MXIOC_FAILURE_STAGE=%s EXIT=%s\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v systemctl >/dev/null || { echo 'Standalone cores require systemd'; exit 12; }
if ! command -v curl >/dev/null || ! command -v flock >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y curl util-linux
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux
  elif command -v yum >/dev/null; then yum install -y curl util-linux
  else echo 'Missing curl/flock or unsupported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || { echo 'Another MXIOC installation is running'; exit 75; }
workdir=$(mktemp -d /tmp/mxioc-core.XXXXXXXX)
installer="$workdir/install.sh"
backup=$(mktemp /tmp/mxioc-config.XXXXXXXX)
candidate=''
had_config=0
applied=0
cleanup() {
  rc=$?
  if [ "$rc" != 0 ] && [ "$applied" = 1 ]; then
    if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json; else rm -f /etc/sing-box/config.json; fi
    systemctl restart sing-box >/dev/null 2>&1 || true
  fi
  rm -rf -- "$workdir"
  rm -f "$backup"
  [ -z "$candidate" ] || rm -f "$candidate"
}
trap cleanup EXIT
if [ -f /etc/sing-box/config.json ]; then cp -p /etc/sing-box/config.json "$backup"; had_config=1; fi
stage=download
printf 'MXIOC_STAGE=download\n'
curl -fLsS --retry 2 --connect-timeout 20 --max-time 180 https://sing-box.app/install.sh -o "$installer"
test -s "$installer"
stage=install
printf 'MXIOC_STAGE=install\n'
applied=1
(cd "$workdir" && bash -e "$installer"  </dev/null)
if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json; fi
stage=config
printf 'MXIOC_STAGE=config\n'
if [ -n '__MXIOC_CONFIG64__' ]; then
  mkdir -p $(dirname /etc/sing-box/config.json)
  candidate=$(mktemp /etc/sing-box/config.json.mxioc.XXXXXXXX)
  printf '%s' '__MXIOC_CONFIG64__' | base64 -d > "$candidate"
  chmod 600 "$candidate"
  /usr/bin/sing-box check -c "$candidate" >/dev/null 2>&1 || { echo 'Core configuration validation failed; configuration was not applied'; exit 22; }
  applied=1
  if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json.mxioc-backup; fi
  # Preserve permissions needed by the vendor service user.
  if [ -f /etc/sing-box/config.json ]; then chown --reference=/etc/sing-box/config.json "$candidate"; chmod --reference=/etc/sing-box/config.json "$candidate"; else chmod 644 "$candidate"; fi
  mv "$candidate" /etc/sing-box/config.json
  candidate=''
fi
/usr/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || { echo 'Core configuration validation failed'; exit 22; }
stage=service
printf 'MXIOC_STAGE=service\n'
systemctl enable sing-box
systemctl restart sing-box
sleep 2
systemctl is-active --quiet sing-box
/usr/bin/sing-box version
printf 'MXIOC_STAGE=installed\n'
