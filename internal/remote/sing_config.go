package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
)

type singConfigKey struct{}
type singLayout struct {
	Binary, Workdir, CommandHash string
	Files, Dirs                  []string
}
type singFile struct {
	Path string
	Raw  []byte
	Doc  Record
}
type singConfig struct {
	Layout singLayout
	Files  []singFile
	Raw    []byte
}

func safeSingPath(p string) bool {
	return strings.HasPrefix(p, "/") && path.Clean(p) == p && p != "/" && len(p) < 2048 && !strings.ContainsAny(p, "\x00\r\n\t")
}

const singDiscoverScript = `set -Eeuo pipefail
systemctl is-active --quiet sing-box
pid=$(systemctl show --property=MainPID --value sing-box)
case "$pid" in ''|0|*[!0-9]*) exit 1;; esac
printf 'BINARY\t';readlink -f /proc/$pid/exe | base64 -w0;printf '\n'
printf 'CWD\t';readlink -f /proc/$pid/cwd | base64 -w0;printf '\n'
printf 'ARGS\t';base64 -w0 < /proc/$pid/cmdline;printf '\n'
`

func parseSingLayout(raw string) (singLayout, error) {
	var l singLayout
	var args []string
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		p := strings.SplitN(line, "\t", 2)
		if len(p) != 2 {
			return l, errors.New("sing-box 服务信息无效")
		}
		b, e := base64.StdEncoding.DecodeString(p[1])
		if e != nil {
			return l, e
		}
		switch p[0] {
		case "BINARY":
			l.Binary = strings.TrimSuffix(string(b), "\n")
		case "CWD":
			l.Workdir = strings.TrimSuffix(string(b), "\n")
		case "ARGS":
			args = strings.Split(strings.TrimSuffix(string(b), "\x00"), "\x00")
			l.CommandHash = coreConfigHash(b)
		}
	}
	if !safeSingPath(l.Binary) || (!safeSingPath(l.Workdir) && l.Workdir != "/") || len(args) < 2 {
		return l, errors.New("无法识别 sing-box 程序或工作目录")
	}
	run := false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		key, val, has := strings.Cut(arg, "=")
		switch key {
		case "run":
			if has || run {
				return l, errors.New("sing-box 启动命令无效")
			}
			run = true
		case "-c", "--config", "-C", "--config-directory", "-D", "--directory":
			if !has {
				i++
				if i >= len(args) {
					return l, errors.New("sing-box 启动参数缺少路径")
				}
				val = args[i]
			}
			if !safeSingPath(val) && !((key == "-D" || key == "--directory") && val == "/") {
				return l, errors.New("sing-box 接管目前要求绝对配置路径")
			}
			switch key {
			case "-c", "--config":
				l.Files = append(l.Files, val)
			case "-C", "--config-directory":
				l.Dirs = append(l.Dirs, val)
			case "-D", "--directory":
				if val != l.Workdir {
					return l, errors.New("sing-box 工作目录与实际进程不一致")
				}
			}
		case "--disable-color":
			if has && val != "true" && val != "false" {
				return l, errors.New("sing-box 启动参数无效")
			}
		default:
			return l, errors.New("暂不支持此 sing-box 启动参数：" + key)
		}
	}
	if !run || len(l.Files)+len(l.Dirs) == 0 || len(l.Files)+len(l.Dirs) > 32 {
		return l, errors.New("未找到 sing-box 配置文件或目录")
	}
	return l, nil
}
func (l singLayout) fileListScript() string {
	s := "{\n"
	for _, p := range l.Files {
		s += "printf '%s\\n' " + quote(p) + "\n"
	}
	for _, p := range l.Dirs {
		s += "test -d " + quote(p) + " || exit 76\nfor f in " + quote(p) + "/*.json; do test ! -f \"$f\" || printf '%s\\n' \"$f\"; done\n"
	}
	return s + "} | LC_ALL=C sort\n"
}
func (l singLayout) identityScript() string {
	return `systemctl is-active --quiet sing-box
pid=$(systemctl show --property=MainPID --value sing-box)
case "$pid" in ''|0|*[!0-9]*) exit 76;; esac
actual=$(sha256sum /proc/$pid/cmdline)
test "${actual%% *}" = ` + quote(l.CommandHash) + ` || exit 76
test "$(readlink -f /proc/$pid/exe)" = ` + quote(l.Binary) + ` || exit 76
test "$(readlink -f /proc/$pid/cwd)" = ` + quote(l.Workdir) + ` || exit 76
`
}
func (l singLayout) checkCommand(files []string) string {
	s := "cd " + quote(l.Workdir) + "\n" + quote(l.Binary) + " check -D " + quote(l.Workdir)
	for _, p := range files {
		s += " -c " + quote(p)
	}
	return s + " >/dev/null 2>&1"
}
func newSingConfig(ctx context.Context, run coreRunner) (*singConfig, error) {
	raw, e := run(ctx, singDiscoverScript, 64<<10)
	if e != nil {
		return nil, errors.New("未找到运行中的 sing-box systemd 服务")
	}
	l, e := parseSingLayout(raw)
	if e != nil {
		return nil, e
	}
	return &singConfig{Layout: l}, nil
}
func (s *singConfig) read(ctx context.Context, run coreRunner) ([]byte, Record, error) {
	script := "set -Eeuo pipefail\n" + s.Layout.identityScript() + "files=$(\n" + s.Layout.fileListScript() + ")\ntotal=0; count=0\nwhile IFS= read -r f; do\n" + `test -f "$f" && test ! -L "$f"
size=$(wc -c < "$f"); total=$((total+size)); count=$((count+1))
test "$size" -le 2097152 && test "$total" -le 10485760 && test "$count" -le 64
printf 'FILE\t';printf '%s' "$f" | base64 -w0;printf '\t';base64 -w0 < "$f";printf '\n'
done <<< "$files"
`
	output, e := run(ctx, script, 16<<20)
	if e != nil {
		return nil, nil, errors.New("读取 sing-box 配置失败，服务参数变化、符号链接或文件超过限制")
	}
	var files []singFile
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		p := strings.Split(line, "\t")
		if len(p) != 3 || p[0] != "FILE" {
			return nil, nil, errors.New("sing-box 配置读取结果无效")
		}
		name, ne := base64.StdEncoding.DecodeString(p[1])
		raw, re := base64.StdEncoding.DecodeString(p[2])
		filename := string(name)
		if ne != nil || re != nil || !safeSingPath(filename) || seen[filename] {
			return nil, nil, errors.New("sing-box 配置路径无效或重复")
		}
		seen[filename] = true
		doc, de := decodeProbeJSON(raw)
		if de != nil {
			return nil, nil, fmt.Errorf("sing-box 配置 %s 无法解析", filename)
		}
		files = append(files, singFile{filename, raw, doc})
	}
	if len(files) == 0 {
		return nil, nil, errors.New("sing-box 配置为空")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	merged, e := mergeSingFiles(files)
	if e != nil {
		return nil, nil, e
	}
	raw, e := json.Marshal(merged)
	if e != nil || len(raw) > 2<<20 {
		return nil, nil, errors.New("sing-box 合并配置超过 2 MB")
	}
	s.Files, s.Raw = files, raw
	// Return an independent document: editors must not mutate source snapshots.
	merged, e = decodeProbeJSON(raw)
	return raw, merged, e
}

// sing-box merges in filename order: arrays append, maps recurse, first scalar wins.
func mergeSingValue(first, next any) (any, error) {
	if first == nil {
		return next, nil
	}
	if next == nil {
		return first, nil
	}
	switch old := first.(type) {
	case map[string]any:
		addition, ok := next.(map[string]any)
		if !ok {
			return nil, errors.New("sing-box 配置字段类型冲突")
		}
		out := Record{}
		for k, v := range old {
			out[k] = v
		}
		for k, v := range addition {
			var e error
			if prior, ok := out[k]; ok {
				v, e = mergeSingValue(prior, v)
				if e != nil {
					return nil, e
				}
			}
			out[k] = v
		}
		return out, nil
	case []any:
		out := append([]any{}, old...)
		if list, ok := next.([]any); ok {
			return append(out, list...), nil
		}
		return append(out, next), nil
	default:
		return first, nil
	}
}
func mergeSingFiles(files []singFile) (Record, error) {
	var merged any = Record{}
	for _, file := range files {
		var e error
		merged, e = mergeSingValue(merged, file.Doc)
		if e != nil {
			return nil, e
		}
	}
	return merged.(Record), nil
}
func sameSingValue(a, b any) bool {
	ar, ae := json.Marshal(a)
	br, be := json.Marshal(b)
	return ae == nil && be == nil && string(ar) == string(br)
}

// Partition changed values back to their contributing files. Unchanged values
// retain their original documents and bytes. Refuse ambiguous cross-file reorders.
type singPart struct {
	Value   any
	Present bool
}

func splitSingValue(parts []singPart, next singPart, defaultFile int) ([]singPart, error) {
	var merged any
	owners := []int{}
	for i, p := range parts {
		if p.Present {
			owners = append(owners, i)
			var e error
			merged, e = mergeSingValue(merged, p.Value)
			if e != nil {
				return nil, e
			}
		}
	}
	if next.Present && len(owners) > 0 && sameSingValue(merged, next.Value) {
		return parts, nil
	}
	out := make([]singPart, len(parts))
	if !next.Present {
		return out, nil
	}
	if len(owners) <= 1 {
		owner := defaultFile
		if len(owners) == 1 {
			owner = owners[0]
		}
		out[owner] = next
		return out, nil
	}
	switch value := next.Value.(type) {
	case map[string]any:
		keys := map[string]bool{}
		for k := range value {
			keys[k] = true
		}
		for _, p := range parts {
			if p.Present {
				m, ok := p.Value.(map[string]any)
				if !ok {
					return nil, errors.New("不能改变跨文件字段的类型")
				}
				for k := range m {
					keys[k] = true
				}
			}
		}
		docs := make([]Record, len(parts))
		for i, p := range parts {
			if p.Present {
				docs[i] = Record{}
			}
		}
		for k := range keys {
			children := make([]singPart, len(parts))
			for i, p := range parts {
				if p.Present {
					v, ok := p.Value.(map[string]any)[k]
					children[i] = singPart{v, ok}
				}
			}
			v, ok := value[k]
			result, e := splitSingValue(children, singPart{v, ok}, defaultFile)
			if e != nil {
				return nil, e
			}
			for i, p := range result {
				if p.Present {
					if docs[i] == nil {
						docs[i] = Record{}
					}
					docs[i][k] = p.Value
				}
			}
		}
		for i, d := range docs {
			if d != nil {
				out[i] = singPart{d, true}
			}
		}
	case []any:
		lists := make([][]any, len(parts))
		for _, i := range owners {
			if _, ok := parts[i].Value.([]any); !ok {
				return nil, errors.New("跨文件列表类型不一致")
			}
			lists[i] = []any{}
		}
		used := map[string]bool{}
		for _, item := range value {
			owner := -1
			tag := ""
			if obj, ok := item.(map[string]any); ok {
				tag = valueStringTag(obj)
			}
			if tag != "" {
				if used[tag] {
					return nil, errors.New("跨文件列表存在重复标签")
				}
				used[tag] = true
			}
			for _, i := range owners {
				for _, old := range parts[i].Value.([]any) {
					match := sameSingValue(old, item)
					if tag != "" {
						if obj, ok := old.(map[string]any); ok {
							match = valueStringTag(obj) == tag
						}
					}
					if match {
						if owner >= 0 && owner != i {
							return nil, errors.New("配置列表归属不明确")
						}
						owner = i
					}
				}
			}
			if owner < 0 {
				owner = defaultFile
			}
			if lists[owner] == nil {
				lists[owner] = []any{}
			}
			lists[owner] = append(lists[owner], item)
		}
		for i, list := range lists {
			if list != nil {
				out[i] = singPart{list, true}
			}
		}
	default:
		for i, p := range parts {
			out[i] = p
		}
		out[owners[0]] = next
	}
	var check any
	for _, p := range out {
		if p.Present {
			var e error
			check, e = mergeSingValue(check, p.Value)
			if e != nil {
				return nil, e
			}
		}
	}
	if !sameSingValue(check, next.Value) {
		return nil, errors.New("修改会改变跨文件配置顺序，请按原文件顺序编辑")
	}
	return out, nil
}
func valueStringTag(row Record) string { return value(row["tag"]) }
func (s *singConfig) plan(next Record) ([]singFile, error) {
	parts := make([]singPart, len(s.Files))
	for i, f := range s.Files {
		parts[i] = singPart{f.Doc, true}
	}
	result, e := splitSingValue(parts, singPart{next, true}, len(parts)-1)
	if e != nil {
		return nil, e
	}
	out := make([]singFile, len(s.Files))
	for i, p := range result {
		doc, ok := p.Value.(map[string]any)
		if !ok {
			return nil, errors.New("配置拆分结果无效")
		}
		out[i] = s.Files[i]
		out[i].Doc = doc
		if !sameSingValue(doc, s.Files[i].Doc) {
			out[i].Raw, e = json.MarshalIndent(doc, "", "  ")
			if e != nil {
				return nil, e
			}
			out[i].Raw = append(out[i].Raw, '\n')
		}
	}
	return out, nil
}
