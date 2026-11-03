package remote

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
)

// CoreWriteScript applies a complete validated candidate with an optimistic
// content check and remote rollback. It never interpolates user supplied paths.
func CoreWriteScript(kind string, previous []byte, next Record) (string, error) {
	var path, binary, check string
	switch kind {
	case "xray":
		path = "/usr/local/etc/xray/config.json"
		binary = "/usr/local/bin/xray"
		check = "run -test -config"
	case "sing-box":
		path = "/etc/sing-box/config.json"
		binary = "/usr/bin/sing-box"
		check = "check -c"
	default:
		return "", errors.New("独立内核类型无效")
	}
	var original Record
	decoder := json.NewDecoder(strings.NewReader(string(previous)))
	decoder.UseNumber()
	if decoder.Decode(&original) != nil || original == nil || !json.Valid(previous) || next == nil {
		return "", errors.New("内核配置必须为有效 JSON 对象")
	}
	for _, key := range []string{"inbounds", "outbounds"} {
		if value, exists := next[key]; exists {
			if _, ok := value.([]any); !ok {
				return "", errors.New("内核入站和出站必须为数组")
			}
		}
	}
	raw, err := json.Marshal(next)
	if err != nil || len(raw) > 2<<20 {
		return "", errors.New("内核配置编码失败或超过 2 MB")
	}
	sum := sha256.Sum256(previous)
	prefix := "set -Eeuo pipefail\nconfig=" + quote(path) + "\nexpected=" + quote(hex.EncodeToString(sum[:])) + "\n"
	script := prefix + `exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || exit 75
test -f "$config" && test ! -L "$config"
actual=$(sha256sum "$config")
test "${actual%% *}" = "$expected" || exit 76
candidate=$(mktemp "$config.mxioc.XXXXXXXX")
backup=$(mktemp "$config.backup.XXXXXXXX")
applied=0
cleanup() {
 rc=$?
 trap - EXIT
 if [ "$applied" = 1 ] && [ "$rc" != 0 ]; then
  if cp -p "$backup" "$config" && systemctl restart ` + kind + ` && systemctl is-active --quiet ` + kind + `; then
   printf 'MXIOC_CORE_ROLLED_BACK\n'
  else
   printf 'MXIOC_CORE_ROLLBACK_FAILED\n' >&2
  fi
 fi
 rm -f -- "$candidate"
 exit "$rc"
}
trap cleanup EXIT
cp -p "$config" "$backup"
chmod 0600 "$candidate" "$backup"
printf '%s' ` + quote(base64.StdEncoding.EncodeToString(raw)) + ` | base64 -d > "$candidate"
` + binary + ` ` + check + ` "$candidate" >/dev/null 2>&1
sync -f "$candidate"
actual=$(sha256sum "$config")
test "${actual%% *}" = "$expected" || exit 76
applied=1
mv -f -- "$candidate" "$config"
sync -f "$config"
systemctl restart ` + kind + `
systemctl is-active --quiet ` + kind + `
printf 'MXIOC_CORE_APPLIED\n'
`
	return script, nil
}
