set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\n'
trap 'rc=$?; printf "\nMXIOC_FAILURE_STAGE=%s EXIT=%s\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v bash >/dev/null
if ! command -v curl >/dev/null || ! command -v flock >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y curl util-linux
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux
  elif command -v yum >/dev/null; then yum install -y curl util-linux
  elif command -v apk >/dev/null; then apk add --no-cache curl util-linux
  else echo 'Missing curl/flock and no supported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || { echo 'Another MXIOC 3x-ui installation is still running'; exit 75; }
stage=download
printf 'MXIOC_STAGE=download\n'
installer=$(mktemp /tmp/mxioc-xui.XXXXXXXX)
chmod 700 "$installer"
trap 'rm -f -- "$installer"' EXIT
curl -fLsS --retry 2 --connect-timeout 20 --max-time 180 https://raw.githubusercontent.com/Teminuosi/3x-ui/main/install.sh -o "$installer"
test -s "$installer"
stage=install
printf 'MXIOC_STAGE=install\n'
__MXIOC_ENV__ bash "$installer" </dev/null
stage=credentials
printf 'MXIOC_STAGE=credentials\n'
cd /usr/local/x-ui
./x-ui setting -username __MXIOC_USER__ -password __MXIOC_PASSWORD__ >/dev/null
stage=service
printf 'MXIOC_STAGE=service\n'
if command -v systemctl >/dev/null; then
  systemctl restart x-ui
  for attempt in $(seq 1 20); do systemctl is-active --quiet x-ui && break; sleep 1; done
  systemctl is-active --quiet x-ui
else
  rc-service x-ui restart
  rc-service x-ui status
fi
printf 'MXIOC_STAGE=installed\n'
