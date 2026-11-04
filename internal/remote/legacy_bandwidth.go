package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"sort"
	"strconv"
	"strings"
)

func legacyBandwidthRules(policies Record) (string, error) {
	ids := make([]int, 0, len(policies))
	for key := range policies {
		id, err := strconv.Atoi(key)
		if err != nil || id < 1 || strconv.Itoa(id) != key {
			return "", errors.New("旧限速记录的入站 ID 无效")
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var out strings.Builder
	out.WriteString("table inet mxioc_bandwidth {\n")
	for _, direction := range []string{"upload", "download"} {
		hook, portField := "input", "dport"
		if direction == "download" {
			hook, portField = "output", "sport"
		}
		fmt.Fprintf(&out, "chain %s { type filter hook %s priority -5; policy accept;\n", direction, hook)
		for _, id := range ids {
			row, ok := policies[strconv.Itoa(id)].(Record)
			if !ok {
				return "", errors.New("旧限速记录格式无效")
			}
			port, err := parsedPort(row["port"], 0)
			raw, _ := row["protocols"].([]any)
			protocols := anyStrings(raw)
			rate, rateErr := strconv.Atoi(value(row[direction+"Kbps"]))
			if err != nil || port == 0 || rateErr != nil || rate < 0 || rate > 10_000_000 ||
				(rate != 0 && rate < 100) || len(raw) != len(protocols) || len(protocols) == 0 || len(protocols) > 2 {
				return "", errors.New("旧限速记录包含无效参数")
			}
			for _, protocol := range protocols {
				if protocol != "tcp" && protocol != "udp" {
					return "", errors.New("旧限速协议无效")
				}
			}
			if rate != 0 {
				bytes := rate * 125
				fmt.Fprintf(&out, "meta l4proto { %s } th %s %d limit rate over %d bytes/second burst %d bytes counter drop comment \"mxioc-%d-%s\"\n",
					strings.Join(protocols, ", "), portField, port, bytes, max(65536, bytes/5), id, direction)
			}
		}
		out.WriteString("}\n")
	}
	out.WriteString("}\n")
	return out.String(), nil
}

func clearLegacyBandwidthScript(policies Record, id int) (string, error) {
	previous, err := legacyBandwidthRules(policies)
	if err != nil {
		return "", err
	}
	remaining := maps.Clone(policies)
	key := strconv.Itoa(id)
	policy, ok := policies[key].(Record)
	if !ok {
		return "", errors.New("旧限速记录不存在")
	}
	count := 0
	for _, direction := range []string{"uploadKbps", "downloadKbps"} {
		rate, _ := strconv.Atoi(value(policy[direction])) // Validated by legacyBandwidthRules.
		if rate != 0 {
			count++
		}
	}
	delete(remaining, key)
	next, err := legacyBandwidthRules(remaining)
	if err != nil {
		return "", err
	}
	encode := func(s string) string { return quote(base64.StdEncoding.EncodeToString([]byte(s))) }
	return "set -Eeuo pipefail\nold=" + encode(previous) + "\nnext=" + encode(next) +
		"\nid=" + key + "\ncount=" + strconv.Itoa(count) + "\n" + legacyBandwidthClear, nil
}

const legacyBandwidthClear = `
command -v nft >/dev/null && command -v unshare >/dev/null || exit 12
exec 9>/var/lock/mxioc-bandwidth.lock
flock -n 9 || exit 75
dir=/etc/mxioc-bandwidth
saved="$dir/rules.nft"
[ -d "$dir" ] && [ ! -L "$dir" ] && [ -f "$saved" ] && [ ! -L "$saved" ] || exit 76
work=$(mktemp -d "$dir/.clear.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf '%s' "$old" | base64 -d > "$work/old"
printf '%s' "$next" | base64 -d > "$work/next"
chmod 600 "$work/next"
{ cmp -s "$saved" "$work/old" || cmp -s "$saved" "$work/next"; } || exit 76
canonicalize() {
  unshare -n sh -ec 'nft -f "$1"; nft -s list table inet mxioc_bandwidth' sh "$1"
}
canonicalize "$work/old" > "$work/old-live" || exit 12
canonicalize "$work/next" > "$work/next-live" || exit 12
nft -s list table inet mxioc_bandwidth > "$work/live" || exit 76
if ! cmp -s "$work/live" "$work/next-live"; then
  cmp -s "$work/live" "$work/old-live" || exit 76
  for chain in upload download; do
    nft -a list chain inet mxioc_bandwidth "$chain" |
      awk -v chain="$chain" -v marker="\"mxioc-$id-$chain\"" '
        index($0, "comment " marker " ") && $(NF-1) == "handle" && $NF ~ /^[0-9]+$/ {
          print "delete rule inet mxioc_bandwidth " chain " handle " $NF
        }' >> "$work/remove"
  done
  [ "$count" -gt 0 ] && [ "$(wc -l < "$work/remove")" -eq "$count" ] || exit 76
  nft -c -f "$work/remove"
  nft -s list table inet mxioc_bandwidth > "$work/live"
  cmp -s "$work/live" "$work/old-live" || exit 76
  nft -f "$work/remove"
  nft -s list table inet mxioc_bandwidth > "$work/live"
  cmp -s "$work/live" "$work/next-live" || exit 76
fi
mv -f -- "$work/next" "$saved"
printf 'MXIOC_LEGACY_BANDWIDTH_CLEARED\n'
`

func (m *Manager) ClearLegacyBandwidth(ctx context.Context, server string, id, port int) error {
	record, err := m.Record(server)
	if err != nil {
		return err
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		_, err := m.withCore(ctx, server, func(ctx context.Context, _ string, record Record, run coreRunner) (Record, error) {
			return nil, m.clearLegacyBandwidth(ctx, record, id, port, run)
		})
		return err
	}
	_, err = m.WithPanel(ctx, server, func(panel *Panel, record Record) (any, error) {
		return nil, m.clearLegacyBandwidth(ctx, record, id, port, panel.run)
	})
	return err
}

func (m *Manager) clearLegacyBandwidth(ctx context.Context, record Record, id, port int, run coreRunner) error {
	if id < 1 || port < 1 || port > 65535 {
		return errors.New("旧限速绑定身份无效")
	}
	if value(record["coreUserPending"]) != "" {
		return errors.New("独立内核操作待核对，请先完成原操作")
	}
	policies, err := inboundObject(record["bandwidths"])
	if err != nil {
		return err
	}
	cleared, err := inboundObject(record["goBandwidthCleared"])
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	if policies[key] == nil {
		if value(cleared[key]) == strconv.Itoa(port) {
			return nil
		}
		return errors.New("服务器没有对应的旧限速记录，无法核对归属")
	}
	policy, ok := policies[key].(Record)
	if !ok || value(policy["port"]) != strconv.Itoa(port) {
		return errors.New("限速端口和旧订阅绑定不一致")
	}
	script, err := clearLegacyBandwidthScript(policies, id)
	if err != nil {
		return err
	}
	output, err := run(ctx, script, 8<<10)
	if err != nil || strings.TrimSpace(output) != "MXIOC_LEGACY_BANDWIDTH_CLEARED" {
		var code remoteExitError
		if errors.As(err, &code) {
			switch code {
			case 12:
				return errors.New("远端需要 nftables 和创建临时网络命名空间的权限")
			case 75:
				return errors.New("远端正在处理限速规则，请稍后重试")
			case 76:
				return errors.New("远端限速规则与旧记录不一致，清理结果需核对")
			}
		}
		return errors.New("旧限速规则清理未确认，请重试核对")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	fresh, err := find(data, value(record["id"]))
	if err != nil {
		return err
	}
	delete(policies, key)
	cleared[key] = port
	fresh["bandwidths"], fresh["goBandwidthCleared"] = policies, cleared
	if err := m.flush(data); err != nil {
		return errors.New("远端限速已清理，总控保存待重试")
	}
	return nil
}
