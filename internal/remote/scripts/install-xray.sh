set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\n'
trap 'rc=$?; printf "MXIOC_FAILURE_STAGE=%s EXIT=%s\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v systemctl >/dev/null || { echo 'Standalone cores require systemd'; exit 12; }
if ! command -v curl >/dev/null || ! command -v flock >/dev/null || ! command -v unzip >/dev/null || ! command -v sha256sum >/dev/null || ! command -v timeout >/dev/null; then
  if command -v apt-get >/dev/null; then DEBIAN_FRONTEND=noninteractive apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y curl util-linux unzip coreutils ca-certificates
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux unzip coreutils ca-certificates
  elif command -v yum >/dev/null; then yum install -y curl util-linux unzip coreutils ca-certificates
  else echo 'Missing curl/flock or unsupported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || { echo 'Another MXIOC installation is running'; exit 75; }
if [ -L /usr/local/bin/xray ] || [ -L /usr/local/etc/xray/config.json ]; then echo 'Refusing to replace a symlinked xray binary or configuration'; exit 12; fi
workdir=$(mktemp -d /tmp/mxioc-core.XXXXXXXX)
backup=$(mktemp /tmp/mxioc-config.XXXXXXXX)
candidate=''
had_config=0
applied=0
had_binary=0
was_active=0
was_enabled=0
had_unit=0
created_unit=0
binary_candidate=''
unit_candidate=''
cleanup() {
  rc=$?
  if [ "$rc" != 0 ] && [ "$applied" = 1 ]; then
    rollback_failed=0
    if [ "$had_binary" = 1 ]; then
      binary_candidate=$(mktemp /usr/local/bin/xray.restore.XXXXXXXX) || rollback_failed=1
      if [ -n "$binary_candidate" ]; then cp --preserve=all "$workdir/previous-xray" "$binary_candidate" && mv -f "$binary_candidate" /usr/local/bin/xray || rollback_failed=1; fi
    else rm -f /usr/local/bin/xray || rollback_failed=1; fi
    if [ "$had_config" = 1 ]; then cp -p "$backup" /usr/local/etc/xray/config.json || rollback_failed=1; else rm -f /usr/local/etc/xray/config.json || rollback_failed=1; fi
    if [ "$had_unit" = 1 ] || [ "$created_unit" = 1 ]; then
      if [ "$was_enabled" = 1 ]; then systemctl enable xray >/dev/null 2>&1 || rollback_failed=1; else systemctl disable xray >/dev/null 2>&1 || rollback_failed=1; fi
      if [ "$was_active" = 1 ]; then
        systemctl restart xray >/dev/null 2>&1 || rollback_failed=1
        sleep 2
        systemctl is-active --quiet xray || rollback_failed=1
      else
        systemctl stop xray >/dev/null 2>&1 || rollback_failed=1
        if systemctl is-active --quiet xray; then rollback_failed=1; fi
      fi
    fi
    if [ "$created_unit" = 1 ]; then
      rm -f /etc/systemd/system/xray.service || rollback_failed=1
      systemctl daemon-reload >/dev/null 2>&1 || rollback_failed=1
    fi
    if [ "$rollback_failed" = 1 ]; then echo 'MXIOC_ROLLBACK_FAILED'; else echo 'MXIOC_ROLLBACK_RESTORED'; fi
  fi
  if [ "${rollback_failed:-0}" = 1 ]; then
    echo "Recovery copies retained in $workdir and $backup"
    return
  fi
  rm -rf -- "$workdir"
  rm -f "$backup"
  [ -z "$candidate" ] || rm -f "$candidate"
  [ -z "$binary_candidate" ] || rm -f "$binary_candidate"
  [ -z "$unit_candidate" ] || rm -f "$unit_candidate"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
if [ -f /usr/local/bin/xray ]; then cp --preserve=all /usr/local/bin/xray "$workdir/previous-xray"; had_binary=1; fi
if systemctl is-active --quiet xray; then was_active=1; fi
if systemctl is-enabled --quiet xray; then was_enabled=1; fi
if systemctl cat xray >/dev/null 2>&1; then had_unit=1; fi
if [ "$had_unit" = 0 ] && { [ -e /etc/systemd/system/xray.service ] || [ -L /etc/systemd/system/xray.service ]; }; then echo 'Existing service unit could not be inspected'; exit 12; fi
if [ -f /usr/local/etc/xray/config.json ]; then cp -p /usr/local/etc/xray/config.json "$backup"; had_config=1; fi
stage=download
printf 'MXIOC_STAGE=download\n'
# Fixed, checksum-verified release; never execute a downloaded installer.
case "$(uname -m)" in
  x86_64|amd64) asset=Xray-linux-64.zip; archive_sum=e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 ;;
  aarch64|arm64) asset=Xray-linux-arm64-v8a.zip; archive_sum=1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d ;;
  *) echo 'Managed Xray supports linux amd64/arm64 only'; exit 12 ;;
esac
curl -fLsS --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 20 --max-time 300 "https://github.com/XTLS/Xray-core/releases/download/v26.10.31/$asset" -o "$workdir/xray.zip"
printf '%s  %s\n' "$archive_sum" "$workdir/xray.zip" | sha256sum -c -
stage=verify
printf 'MXIOC_STAGE=verify\n'
mkdir -p "$workdir/bin"
unzip -p "$workdir/xray.zip" xray > "$workdir/bin/xray"
chmod 755 "$workdir/bin/xray"
"$workdir/bin/xray" version > "$workdir/version.txt"
grep -q '^Xray 26.10.31 ' "$workdir/version.txt"
if [ -n '__MXIOC_CONFIG64__' ]; then
  printf '%s' '__MXIOC_CONFIG64__' | base64 -d > "$workdir/check.json"
elif [ "$had_config" = 1 ]; then
  cp -p "$backup" "$workdir/check.json"
else
  printf '%s\n' '{"inbounds":[],"outbounds":[{"protocol":"freedom","tag":"direct"}]}' > "$workdir/check.json"
fi
env XRAY_LOCATION_ASSET=/usr/local/share/xray "$workdir/bin/xray" run -test -config "$workdir/check.json" >/dev/null 2>&1 || { echo 'Managed core rejected configuration; existing installation was not changed'; exit 22; }
stage=install
printf 'MXIOC_STAGE=install\n'
applied=1
mkdir -p /usr/local/bin
binary_candidate=$(mktemp /usr/local/bin/xray.mxioc.XXXXXXXX)
cp "$workdir/bin/xray" "$binary_candidate"
chmod 755 "$binary_candidate"
mv -f "$binary_candidate" /usr/local/bin/xray
binary_candidate=''
if [ "$had_config" = 1 ]; then cp -p "$backup" /usr/local/etc/xray/config.json; fi
if [ "$had_unit" = 0 ]; then
  mkdir -p /etc/systemd/system /var/lib/xray
  unit_candidate=$(mktemp /etc/systemd/system/xray.service.mxioc.XXXXXXXX)
  cat > "$unit_candidate" <<'UNIT'
[Unit]
Description=MXIOC managed xray
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/xray
ExecStart=/usr/local/bin/xray run -config /usr/local/etc/xray/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$unit_candidate"
  mv -f "$unit_candidate" /etc/systemd/system/xray.service
  unit_candidate=''
  created_unit=1
  systemctl daemon-reload
fi
stage=config
printf 'MXIOC_STAGE=config\n'
mkdir -p /usr/local/etc/xray
candidate=$(mktemp /usr/local/etc/xray/config.json.mxioc.XXXXXXXX)
cp "$workdir/check.json" "$candidate"
chmod 600 "$candidate"
env XRAY_LOCATION_ASSET=/usr/local/share/xray /usr/local/bin/xray run -test -config "$candidate" >/dev/null 2>&1 || { echo 'Core configuration validation failed; configuration was not applied'; exit 22; }
if [ "$had_config" = 1 ]; then cp -p "$backup" /usr/local/etc/xray/config.json.mxioc-backup; fi
# Preserve permissions needed by an existing service user.
if [ -f /usr/local/etc/xray/config.json ]; then chown --reference=/usr/local/etc/xray/config.json "$candidate"; chmod --reference=/usr/local/etc/xray/config.json "$candidate"; fi
mv "$candidate" /usr/local/etc/xray/config.json
candidate=''
env XRAY_LOCATION_ASSET=/usr/local/share/xray /usr/local/bin/xray run -test -config /usr/local/etc/xray/config.json >/dev/null 2>&1 || { echo 'Core configuration validation failed'; exit 22; }
stage=service
printf 'MXIOC_STAGE=service\n'
systemctl enable xray
systemctl restart xray
sleep 2
systemctl is-active --quiet xray
/usr/local/bin/xray version
printf 'MXIOC_STAGE=installed\n'
