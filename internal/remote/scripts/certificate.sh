set -eu
umask 077
export LC_ALL=C
acme_home=/var/lib/mxioc-acme
mkdir -p "$acme_home"
chmod 700 "$acme_home"
command -v flock >/dev/null || { echo '缺少 flock，请安装 util-linux'; exit 1; }
exec 9>"$acme_home/operation.lock"
flock -n 9 || { echo '证书签发或续期正在运行，请稍后重试'; exit 1; }
for dependency in openssl curl getent sha256sum timeout systemctl; do
 command -v "$dependency" >/dev/null || { echo "缺少依赖: $dependency"; exit 1; }
done
cert_valid() {
 test -s "$cert_dir/fullchain.pem" && test -s "$cert_dir/privkey.pem" &&
 openssl x509 -in "$cert_dir/fullchain.pem" -checkend 604800 -noout >/dev/null 2>&1 &&
 openssl verify -untrusted "$cert_dir/fullchain.pem" -verify_hostname "$cert_domain" "$cert_dir/fullchain.pem" >/dev/null 2>&1
}
if ! cert_valid; then
 if [ -z "${cert_dns:-}" ]; then
dns_ips=$(getent ahosts "$cert_domain" | awk '{print $1}' | sort -u)
[ -n "$dns_ips" ] || { echo '域名未解析，尚未创建节点'; exit 1; }
local_ips=$(ip -o addr show scope global | awk '{split($4,a,"/");print a[1]}'; printf '%s\n' "$expected_ip")
for address in $dns_ips; do
 printf '%s\n' "$local_ips" | grep -Fxq "$address" || { echo "域名解析到 $address，未指向当前服务器；请核对 A/AAAA 并关闭 CDN 代理"; exit 1; }
done
 ss -H -lnt 'sport = :80' | grep -q . && { echo 'TCP 80 已被占用，请使用已有证书或释放验证端口；不会停止现有网站'; exit 1; }
 if ! command -v socat >/dev/null; then
  if command -v apt-get >/dev/null; then
   DEBIAN_FRONTEND=noninteractive timeout 90 apt-get install -y --no-install-recommends socat
  elif command -v dnf >/dev/null; then timeout 90 dnf install -y socat
  elif command -v yum >/dev/null; then timeout 90 yum install -y socat
  else echo '缺少 socat，请先通过系统包管理器安装'; exit 1; fi
 fi
 fi
 if [ ! -x "$acme_home/acme.sh" ]; then
  bootstrap_dir=$(mktemp -d "$acme_home/bootstrap.XXXXXX")
  bootstrap="$bootstrap_dir/acme.sh"
  trap 'rm -f -- "$bootstrap"; rmdir -- "$bootstrap_dir"' EXIT
  curl -fLsS --connect-timeout 10 --max-time 35 --proto '=https' 'https://raw.githubusercontent.com/acmesh-official/acme.sh/37d064f7b580055d3f2ddf9a9c960f754f3694d6/acme.sh' -o "$bootstrap"
  printf '%s  %s\n' 'fa4842619ddf50f774d79092ae06887a2107c660757283b763bef834dfc150ff' "$bootstrap" | sha256sum -c - >/dev/null
  (cd "$bootstrap_dir" && sh ./acme.sh --install --home "$acme_home" --nocron --noprofile)
  rm -f -- "$bootstrap"
  rmdir -- "$bootstrap_dir"
  trap - EXIT
 fi
 # No --force: retries retain ACME state and do not blindly create new orders.
 if [ -n "${cert_dns:-}" ]; then
  mkdir -p "$acme_home/dnsapi"
  plugin=$(mktemp "$acme_home/dnsapi/download.XXXXXX")
  trap 'rm -f -- "$plugin"' EXIT
  curl -fLsS --connect-timeout 10 --max-time 35 --proto '=https' "https://raw.githubusercontent.com/acmesh-official/acme.sh/37d064f7b580055d3f2ddf9a9c960f754f3694d6/dnsapi/$cert_dns.sh" -o "$plugin"
  printf '%s  %s\n' "$cert_dns_hash" "$plugin" | sha256sum -c - >/dev/null
  chmod 600 "$plugin"
  mv "$plugin" "$acme_home/dnsapi/$cert_dns.sh"
  trap - EXIT
  # acme.sh stores provider credentials under this root-only home for automatic renewal.
  timeout 420 "$acme_home/acme.sh" --issue --home "$acme_home" --server letsencrypt --dns "$cert_dns" -d "$cert_domain" --keylength ec-256
 else
 timeout 140 "$acme_home/acme.sh" --issue --home "$acme_home" --server letsencrypt --standalone -d "$cert_domain" --keylength ec-256
 fi
 mkdir -p "$cert_dir"
 chmod 755 /etc/mxioc-certificates "$cert_dir"
 owner=$(systemctl show -p User --value "$cert_service.service")
 owner=${owner:-root}
 printf '%s\n' "$owner" | grep -Eq '^[a-zA-Z_][a-zA-Z0-9_-]*[$]?$' || { echo '服务用户格式异常，证书未安装'; exit 1; }
 id -- "$owner" >/dev/null
 hook="$cert_dir/reload.sh"
 printf '#!/bin/sh\nset -eu\nchown %s %s\nchmod 600 %s\nif [ ! -e %s ]; then touch %s; exit 0; fi\nsystemctl try-reload-or-restart %s.service\n' "$owner" "$cert_dir/privkey.pem" "$cert_dir/privkey.pem" "$cert_dir/.ready" "$cert_dir/.ready" "$cert_service" > "$hook"
 chmod 700 "$hook"
 "$acme_home/acme.sh" --install-cert --home "$acme_home" -d "$cert_domain" --ecc --key-file "$cert_dir/privkey.pem" --fullchain-file "$cert_dir/fullchain.pem" --reloadcmd "$hook"
fi
cert_valid || { echo '证书验证失败，尚未创建节点'; exit 1; }
cert_pub=$(openssl x509 -in "$cert_dir/fullchain.pem" -pubkey -noout | openssl pkey -pubin -outform DER | sha256sum)
key_pub=$(openssl pkey -in "$cert_dir/privkey.pem" -pubout -outform DER | sha256sum)
[ "$cert_pub" = "$key_pub" ] || { echo '证书与私钥不匹配，尚未创建节点'; exit 1; }
cat > /etc/systemd/system/mxioc-acme-renew.service <<'UNIT'
[Unit]
Description=Renew MXIOC managed TLS certificates
After=network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/flock -w 300 /var/lib/mxioc-acme/operation.lock /bin/sh /var/lib/mxioc-acme/acme.sh --cron --home /var/lib/mxioc-acme
UNIT
cat > /etc/systemd/system/mxioc-acme-renew.timer <<'UNIT'
[Unit]
Description=Check MXIOC certificates daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now mxioc-acme-renew.timer >/dev/null
printf 'MXIOC_CERT_READY\n'
