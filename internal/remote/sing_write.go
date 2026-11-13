package remote

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

func (s *singConfig) guardScript() string {
	names := []string{}
	for _, f := range s.Files {
		names = append(names, f.Path)
	}
	script := s.Layout.identityScript() + "files=$(\n" + s.Layout.fileListScript() + ")\nactual=$(printf '%s\\n' \"$files\" | sha256sum)\ntest \"${actual%% *}\" = " + quote(coreConfigHash([]byte(strings.Join(names, "\n")+"\n"))) + " || exit 76\n"
	for _, f := range s.Files {
		script += "test -f " + quote(f.Path) + " && test ! -L " + quote(f.Path) + " || exit 76\nactual=$(sha256sum " + quote(f.Path) + ")\ntest \"${actual%% *}\" = " + quote(coreConfigHash(f.Raw)) + " || exit 76\n"
	}
	return script
}
func (s *singConfig) writeScript(previous []byte, next Record, managedTag, verify string, cancelKey ...string) (string, error) {
	if string(previous) != string(s.Raw) || len(s.Files) == 0 {
		return "", errors.New("sing-box 配置快照已变化，请重新读取")
	}
	original, e := decodeProbeJSON(previous)
	if e != nil {
		return "", e
	}
	if e = protectCoreInbounds(original, next, managedTag); e != nil {
		return "", e
	}
	planned, e := s.plan(next)
	if e != nil {
		return "", e
	}
	script := `set -Eeuo pipefail
exec 9>/var/lock/mxioc-xui-install.lock
flock -n 9 || exit 75
`
	if len(cancelKey) > 0 {
		key := cancelKey[0]
		raw, e := hex.DecodeString(key)
		if e != nil || len(raw) != 32 || len(key) != 64 {
			return "", errors.New("创建取消标识无效")
		}
		script += "[ ! -e " + quote(coreCreateFencePath(key)) + " ] || exit 77\n"
	}
	script += s.guardScript()
	script += `stage=''; backup=''; applied=0
candidates=(); targets=(); copies=()
cleanup() {
 rc=$?
 trap - EXIT
 trap '' TERM INT
 if [ "$applied" = 1 ] && [ "$rc" != 0 ]; then
  restored=1
  for ((i=0;i<${#targets[@]};i++)); do cp -p -- "${copies[$i]}" "${targets[$i]}" || restored=0; done
  if [ "$restored" = 1 ] && systemctl restart sing-box && systemctl is-active --quiet sing-box; then
   printf 'MXIOC_CORE_ROLLED_BACK\n'
  else
   printf 'MXIOC_CORE_ROLLBACK_FAILED\n' >&2
  fi
 fi
 for candidate in "${candidates[@]}"; do rm -f -- "$candidate"; done
 [ -z "$stage" ] || rm -rf -- "$stage"
 exit "$rc"
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
umask 077
stage=$(mktemp -d /tmp/mxioc-sing-check.XXXXXXXX)
mkdir -p /var/backups
backup=$(mktemp -d /var/backups/mxioc-singbox.XXXXXXXX)
`
	for i, file := range planned {
		staged := fmt.Sprintf("\"$stage/%04d.json\"", i)
		if string(file.Raw) == string(s.Files[i].Raw) {
			script += "cp -p -- " + quote(file.Path) + " " + staged + "\n"
			continue
		}
		script += "targets+=(" + quote(file.Path) + ")\ncopies+=(\"$backup/" + fmt.Sprint(i) + "\")\ncp -p -- " + quote(file.Path) + " \"$backup/" + fmt.Sprint(i) + "\"\n"
		script += "candidate=$(mktemp " + quote(file.Path+".mxioc.XXXXXXXX") + ")\ncandidates+=(\"$candidate\")\nprintf '%s' " + quote(base64.StdEncoding.EncodeToString(file.Raw)) + " | base64 -d > \"$candidate\"\nchown --reference=" + quote(file.Path) + " \"$candidate\"\nchmod --reference=" + quote(file.Path) + " \"$candidate\"\nsync -f \"$candidate\"\ncp -p -- \"$candidate\" " + staged + "\n"
	}
	script += "set --\n"
	for i := range planned {
		script += fmt.Sprintf("set -- \"$@\" -c \"$stage/%04d.json\"\n", i)
	}
	script += "cd " + quote(s.Layout.Workdir) + "\nif ! " + quote(s.Layout.Binary) + " check -D " + quote(s.Layout.Workdir) + " \"$@\" >/dev/null 2>&1; then printf 'MXIOC_CORE_VALIDATION_FAILED\\n';exit 1;fi\n"
	script += s.guardScript()
	script += `applied=1
for ((i=0;i<${#targets[@]};i++)); do mv -f -- "${candidates[$i]}" "${targets[$i]}";sync -f "${targets[$i]}";done
systemctl restart sing-box
systemctl is-active --quiet sing-box
` + verify + "\nprintf 'MXIOC_CORE_APPLIED\\n'\n"
	return script, nil
}
