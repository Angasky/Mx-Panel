set -Eeuo pipefail
stage=preflight
printf 'MXIOC_STAGE=preflight\n'
trap 'rc=$?; printf "MXIOC_FAILURE_STAGE=%s EXIT=%s\n" "$stage" "$rc"; exit "$rc"' ERR
test "$(id -u)" = 0
command -v systemctl >/dev/null || { echo 'Standalone cores require systemd'; exit 12; }
if ! command -v curl >/dev/null || ! command -v flock >/dev/null || ! command -v tar >/dev/null || ! command -v sha256sum >/dev/null || ! command -v timeout >/dev/null; then
  if command -v apt-get >/dev/null; then apt-get update && apt-get install -y curl util-linux tar gzip coreutils ca-certificates
  elif command -v dnf >/dev/null; then dnf install -y curl util-linux tar gzip coreutils ca-certificates
  elif command -v yum >/dev/null; then yum install -y curl util-linux tar gzip coreutils ca-certificates
  else echo 'Missing curl/flock or unsupported package manager'; exit 12; fi
fi
mkdir -p /var/lock
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || { echo 'Another MXIOC installation is running'; exit 75; }
if [ -L /usr/bin/sing-box ] || [ -L /etc/sing-box/config.json ]; then echo 'Refusing to replace a symlinked sing-box binary or configuration'; exit 12; fi
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
      binary_candidate=$(mktemp /usr/bin/sing-box.restore.XXXXXXXX) || rollback_failed=1
      if [ -n "$binary_candidate" ]; then cp --preserve=all "$workdir/previous-sing-box" "$binary_candidate" && mv -f "$binary_candidate" /usr/bin/sing-box || rollback_failed=1; fi
    else rm -f /usr/bin/sing-box || rollback_failed=1; fi
    if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json || rollback_failed=1; else rm -f /etc/sing-box/config.json || rollback_failed=1; fi
    if [ "$had_unit" = 1 ] || [ "$created_unit" = 1 ]; then
      if [ "$was_enabled" = 1 ]; then systemctl enable sing-box >/dev/null 2>&1 || rollback_failed=1; else systemctl disable sing-box >/dev/null 2>&1 || rollback_failed=1; fi
      if [ "$was_active" = 1 ]; then
        systemctl restart sing-box >/dev/null 2>&1 || rollback_failed=1
        sleep 2
        systemctl is-active --quiet sing-box || rollback_failed=1
      else
        systemctl stop sing-box >/dev/null 2>&1 || rollback_failed=1
        if systemctl is-active --quiet sing-box; then rollback_failed=1; fi
      fi
    fi
    if [ "$created_unit" = 1 ]; then
      rm -f /etc/systemd/system/sing-box.service || rollback_failed=1
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
if [ -f /usr/bin/sing-box ]; then cp --preserve=all /usr/bin/sing-box "$workdir/previous-sing-box"; had_binary=1; fi
if systemctl is-active --quiet sing-box; then was_active=1; fi
if systemctl is-enabled --quiet sing-box; then was_enabled=1; fi
if systemctl cat sing-box >/dev/null 2>&1; then had_unit=1; fi
if [ "$had_unit" = 0 ] && { [ -e /etc/systemd/system/sing-box.service ] || [ -L /etc/systemd/system/sing-box.service ]; }; then echo 'Existing service unit could not be inspected'; exit 12; fi
if [ -f /etc/sing-box/config.json ]; then cp -p /etc/sing-box/config.json "$backup"; had_config=1; fi
stage=download
printf 'MXIOC_STAGE=download\n'
# Build outside system paths. Neither a global Go installation nor a Python
# runtime is required; the temporary toolchain and caches are removed on exit.
case "$(uname -m)" in
  x86_64|amd64) goarch=amd64; gosum=ccfe7ae822d2c2f41f4fe7c956199967a4dac22d0ee0d2b2bfdb440aab3b20c5 ;;
  aarch64|arm64) goarch=arm64; gosum=3f4227ce7b206a513e794f1393adb473a07b46e94d18bd15d1c684bbb7319797 ;;
  *) echo 'Managed sing-box build supports linux amd64/arm64 only'; exit 12 ;;
esac
curl -fLsS --proto '=https' --tlsv1.2 --retry 2 --connect-timeout 20 --max-time 300 "https://go.dev/dl/go1.26.10.linux-$goarch.tar.gz" -o "$workdir/go.tar.gz"
printf '%s  %s\n' "$gosum" "$workdir/go.tar.gz" | sha256sum -c -
tar -xzf "$workdir/go.tar.gz" -C "$workdir"
stage=build
printf 'MXIOC_STAGE=build\n'
mkdir -p "$workdir/bin" "$workdir/home" "$workdir/buildtmp"
env GOENV=off GOWORK=off GOFLAGS='' GOTOOLCHAIN=local CGO_ENABLED=0 GOMAXPROCS=2 GOOS=linux GOARCH="$goarch" GOROOT="$workdir/go" GOINSECURE='' GOCACHEPROG='' \
  GOPROXY=https://proxy.golang.org GOSUMDB=sum.golang.org GOPRIVATE='' GONOSUMDB='' GONOPROXY='' \
  GOPATH="$workdir/gopath" GOMODCACHE="$workdir/gopath/pkg/mod" GOCACHE="$workdir/cache" GOTMPDIR="$workdir/buildtmp" GOBIN="$workdir/bin" HOME="$workdir/home" \
  timeout 1800 "$workdir/go/bin/go" install -p 2 -trimpath -tags 'with_quic,with_utls,with_v2ray_api' \
  -ldflags '-s -w -X github.com/sagernet/sing-box/constant.Version=1.14.4' \
  github.com/sagernet/sing-box/cmd/sing-box@v1.14.4
"$workdir/bin/sing-box" version > "$workdir/version.txt"
grep -q 'with_v2ray_api' "$workdir/version.txt"
grep -q 'with_quic' "$workdir/version.txt"
if [ -n '__MXIOC_CONFIG64__' ]; then
  printf '%s' '__MXIOC_CONFIG64__' | base64 -d > "$workdir/check.json"
elif [ "$had_config" = 1 ]; then
  cp -p "$backup" "$workdir/check.json"
else
  printf '%s\n' '{"inbounds":[],"outbounds":[{"type":"direct","tag":"direct"}]}' > "$workdir/check.json"
fi
"$workdir/bin/sing-box" check -c "$workdir/check.json" >/dev/null 2>&1 || { echo 'Managed core rejected configuration; existing installation was not changed'; exit 22; }
stage=install
printf 'MXIOC_STAGE=install\n'
applied=1
mkdir -p /usr/bin
binary_candidate=$(mktemp /usr/bin/sing-box.mxioc.XXXXXXXX)
cp "$workdir/bin/sing-box" "$binary_candidate"
chmod 755 "$binary_candidate"
mv -f "$binary_candidate" /usr/bin/sing-box
binary_candidate=''
if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json; fi
if [ "$had_unit" = 0 ]; then
  mkdir -p /etc/systemd/system /var/lib/sing-box
  unit_candidate=$(mktemp /etc/systemd/system/sing-box.service.mxioc.XXXXXXXX)
  cat > "$unit_candidate" <<'UNIT'
[Unit]
Description=MXIOC managed sing-box
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/lib/sing-box
ExecStart=/usr/bin/sing-box run -c /etc/sing-box/config.json
Restart=on-failure
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
UNIT
  chmod 644 "$unit_candidate"
  mv -f "$unit_candidate" /etc/systemd/system/sing-box.service
  unit_candidate=''
  created_unit=1
  systemctl daemon-reload
fi
stage=config
printf 'MXIOC_STAGE=config\n'
mkdir -p /etc/sing-box
candidate=$(mktemp /etc/sing-box/config.json.mxioc.XXXXXXXX)
cp "$workdir/check.json" "$candidate"
chmod 600 "$candidate"
/usr/bin/sing-box check -c "$candidate" >/dev/null 2>&1 || { echo 'Core configuration validation failed; configuration was not applied'; exit 22; }
if [ "$had_config" = 1 ]; then cp -p "$backup" /etc/sing-box/config.json.mxioc-backup; fi
# Preserve permissions needed by an existing service user.
if [ -f /etc/sing-box/config.json ]; then chown --reference=/etc/sing-box/config.json "$candidate"; chmod --reference=/etc/sing-box/config.json "$candidate"; fi
mv "$candidate" /etc/sing-box/config.json
candidate=''
/usr/bin/sing-box check -c /etc/sing-box/config.json >/dev/null 2>&1 || { echo 'Core configuration validation failed'; exit 22; }
stage=service
printf 'MXIOC_STAGE=service\n'
systemctl enable sing-box
systemctl restart sing-box
sleep 2
systemctl is-active --quiet sing-box
/usr/bin/sing-box version
printf 'MXIOC_STAGE=installed\n'
