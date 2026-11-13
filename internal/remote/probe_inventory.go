package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Discovery never adopts, reconciles or writes another panel's configuration.
func probeInventoryOnly(record Record) bool {
	return value(record["probeUUID"]) != "" && value(record["probeSource"]) != "" && value(record["coreState"]) == "" && value(record["existingVerifiedAt"]) == "" && value(record["coreUserPending"]) == "" && record["managed"] != true
}

const probeInventoryScript = `set -eu
{
 for f in /usr/local/etc/xray/config.json /etc/xray/config.json /etc/sing-box/config.json /etc/s-box/sb.json /usr/local/x-ui/bin/config.json; do test ! -f "$f" || printf '%s\n' "$f"; done
 for pid in $(pgrep -x xray 2>/dev/null || true) $(pgrep -x sing-box 2>/dev/null || true); do
  test -r "/proc/$pid/cmdline" || continue
  tr '\000' '\n' < "/proc/$pid/cmdline" | awk 'nextarg {print; nextarg=0} /^(-c|-config|--config|-C|--config-directory)$/ {nextarg=1}' | while IFS= read -r p; do
   case "$p" in /*) if test -d "$p"; then for f in "$p"/*.json; do test ! -f "$f" || printf '%s\n' "$f"; done; elif test -f "$p"; then printf '%s\n' "$p"; fi;; esac
  done
 done
} | sort -u | head -20 | (total=0; while IFS= read -r p; do
 test -r "$p" || continue
 size=$(wc -c < "$p")
 if test "$size" -gt 2097152; then printf 'OVERSIZE\n'; continue; fi
 total=$((total + size))
 if test "$total" -gt 10485760; then printf 'OVERSIZE\n'; break; fi
 printf 'CONFIG\t'; printf '%s' "$p" | base64 | tr -d '\n'; printf '\t'; base64 < "$p" | tr -d '\n'; printf '\n'
done)
`

func (m *Manager) probeInbounds(ctx context.Context, record Record) (Record, error) {
	c, e := m.Connection(value(record["id"]))
	if e != nil {
		return nil, e
	}
	out, e := Execute(ctx, c, probeInventoryScript, 16<<20)
	if e != nil {
		return nil, errors.New("探针服务器 SSH 节点识别失败，请检查连接状态并重试")
	}
	return parseProbeInventory(record, out)
}
func parseProbeInventory(record Record, out string) (Record, error) {
	rows := []any{}
	sources := []string{}
	warnings := []string{}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, "\t")
		if len(parts) != 3 || parts[0] != "CONFIG" {
			warnings = append(warnings, "部分配置超过读取限制或无法识别")
			continue
		}
		path, e := base64.StdEncoding.DecodeString(parts[1])
		if e != nil {
			return nil, errors.New("节点配置来源无效")
		}
		raw, e := base64.StdEncoding.DecodeString(parts[2])
		if e != nil {
			return nil, errors.New("节点配置编码无效")
		}
		var doc Record
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.UseNumber()
		if e = dec.Decode(&doc); e != nil {
			warnings = append(warnings, "配置 "+string(path)+" 不是标准 JSON，未解析")
			continue
		}
		native, ok := doc["inbounds"].([]any)
		if !ok {
			continue
		}
		sources = append(sources, string(path))
		for _, item := range native {
			n, ok := item.(map[string]any)
			if !ok {
				continue
			}
			protocol, port := value(n["protocol"]), value(n["port"])
			kind := "Xray"
			if value(n["type"]) != "" {
				protocol, port, kind = value(n["type"]), value(n["listen_port"]), "sing-box"
			}
			if protocol == "dokodemo-door" || protocol == "tun" || protocol == "direct" {
				continue
			}
			p, e := strconv.Atoi(port)
			if e != nil || p < 1 || p > 65535 {
				continue
			}
			name := value(n["tag"])
			if name == "" {
				name = protocol + ":" + port
			}
			rows = append(rows, Record{"id": len(rows) + 1, "remark": name, "protocol": protocol, "port": p, "coreStatus": "discovered", "discoveryOnly": true, "source": kind + " · " + string(path), "enable": true, "shareLinks": []any{}})
		}
	}
	sort.Strings(sources)
	message := fmt.Sprintf("已识别 %d 个配置中的 %d 个现有入站。当前为只读发现，未接管原面板；需要编辑或分配订阅用户时，请在连接设置中接入实际面板 / 内核。", len(sources), len(rows))
	if len(sources) == 0 {
		message = "SSH 已接入，但未发现支持的节点配置。仅安装探针不会自动生成 VPN 节点；容器内、非标准路径或未运行的内核需手动接入。"
	}
	return Record{"server": publicServer(record), "inbounds": rows, "readOnly": true, "inventoryOnly": true, "discoveryMessage": message, "discoveryWarnings": warnings}, nil
}
