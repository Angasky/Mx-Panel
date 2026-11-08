package remote

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"strings"
)

// CoreWriteScript applies a complete validated candidate with an optimistic
// content check and remote rollback. It never interpolates user supplied paths.
func CoreWriteScript(kind string, previous []byte, next Record) (string, error) {
	return coreWriteScript(kind, previous, next, "", "")
}

func coreWriteScript(kind string, previous []byte, next Record, managedTag, verify string, cancelKey ...string) (string, error) {
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
	if err := protectCoreInbounds(original, next, managedTag); err != nil {
		return "", err
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
 trap '' TERM INT
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
trap 'exit 143' TERM
trap 'exit 130' INT
cp -p "$config" "$backup"
chmod 0600 "$candidate" "$backup"
printf '%s' ` + quote(base64.StdEncoding.EncodeToString(raw)) + ` | base64 -d > "$candidate"
if ! ` + binary + ` ` + check + ` "$candidate" >/dev/null 2>&1; then
 printf 'MXIOC_CORE_VALIDATION_FAILED\n'
 exit 1
fi
sync -f "$candidate"
actual=$(sha256sum "$config")
test "${actual%% *}" = "$expected" || exit 76
applied=1
mv -f -- "$candidate" "$config"
sync -f "$config"
systemctl restart ` + kind + `
systemctl is-active --quiet ` + kind + `
` + verify + `
printf 'MXIOC_CORE_APPLIED\n'
`
	if len(cancelKey) > 0 {
		key := cancelKey[0]
		raw, err := hex.DecodeString(key)
		if err != nil || len(raw) != 32 || len(key) != 64 {
			return "", errors.New("创建取消标识无效")
		}
		script = strings.Replace(script, "flock -n 9 || exit 75\n", "flock -n 9 || exit 75\n[ ! -e "+quote(coreCreateFencePath(key))+" ] || exit 77\n", 1)
	}
	return script, nil
}

// Reserve the legacy and Go managed inbound namespace in the full-config
// editor. Check both sides so a manually added tag cannot claim an identity.
func protectCoreInbounds(previous, next Record, managedTag string) error {
	protected := func(doc Record) (map[string]string, error) {
		rows, _ := doc["inbounds"].([]any)
		result := map[string]string{}
		for _, entry := range rows {
			row, _ := entry.(map[string]any)
			tag := value(row["tag"])
			if tag == managedTag || !strings.HasPrefix(tag, "mxioc-inbound-") {
				continue
			}
			if _, exists := result[tag]; exists {
				return nil, errors.New("内核配置中有重复的总控托管入站标签")
			}
			data, err := json.Marshal(row)
			if err != nil {
				return nil, err
			}
			result[tag] = string(data)
		}
		return result, nil
	}
	before, err := protected(previous)
	if err != nil {
		return err
	}
	after, err := protected(next)
	if err != nil {
		return err
	}
	if !maps.Equal(before, after) {
		return errors.New("整配置编辑不允许新增、修改或删除总控托管入站")
	}
	return nil
}
