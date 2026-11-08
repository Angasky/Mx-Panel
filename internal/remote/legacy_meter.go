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

func legacyMeterRules(meters Record) (string, error) {
	ids := make([]int, 0, len(meters))
	for key := range meters {
		id, err := strconv.Atoi(key)
		if err != nil || id < 1 || strconv.Itoa(id) != key {
			return "", errors.New("旧端口计量入站 ID 无效")
		}
		ids = append(ids, id)
	}
	sort.Ints(ids)
	var rules strings.Builder
	rules.WriteString("add table inet mxioc_usage\n")
	rules.WriteString("add chain inet mxioc_usage input { type filter hook input priority -10; policy accept; }\n")
	rules.WriteString("add chain inet mxioc_usage output { type filter hook output priority -10; policy accept; }\n")
	for _, id := range ids {
		port, err := parsedPort(meters[strconv.Itoa(id)], 0)
		if err != nil || port == 0 {
			return "", errors.New("旧计量端口无效")
		}
		fmt.Fprintf(&rules, "add counter inet mxioc_usage up_%d\nadd counter inet mxioc_usage down_%d\n", id, id)
		fmt.Fprintf(&rules, "add rule inet mxioc_usage input meta l4proto { tcp, udp } th dport %d counter name up_%d\n", port, id)
		fmt.Fprintf(&rules, "add rule inet mxioc_usage output meta l4proto { tcp, udp } th sport %d counter name down_%d\n", port, id)
	}
	return rules.String(), nil
}

func clearLegacyMeterScript(meters Record, id int) (string, error) {
	old, err := legacyMeterRules(meters)
	if err != nil {
		return "", err
	}
	next := maps.Clone(meters)
	delete(next, strconv.Itoa(id))
	remaining, err := legacyMeterRules(next)
	if err != nil {
		return "", err
	}
	encode := func(s string) string { return quote(base64.StdEncoding.EncodeToString([]byte(s))) }
	return "set -Eeuo pipefail\nold=" + encode(old) + "\nnext=" + encode(remaining) +
		"\nid=" + strconv.Itoa(id) + "\n" + legacyMeterClear, nil
}

const legacyMeterClear = `
command -v nft >/dev/null && command -v unshare >/dev/null || exit 12
exec 8>/var/lock/mxioc-meter.lock
flock -n 8 || exit 75
dir=/etc/mxioc-meter
saved="$dir/rules.nft"
[ -d "$dir" ] && [ ! -L "$dir" ] && [ -f "$saved" ] && [ ! -L "$saved" ] || exit 76
work=$(mktemp -d "$dir/.clear.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf '%s' "$old" | base64 -d > "$work/old"
printf '%s' "$next" | base64 -d > "$work/next"
# The Python adapter appends counters and rules in creation order. Order does
# not affect accounting, but chain membership and every statement must match.
normalize() {
  awk '
    { sub(/^[[:space:]]+/, ""); sub(/[[:space:]]+$/, "") }
    /^chain (input|output) \{$/ { section=$2 }
    NF { print section ":" $0 }
    /^}$/ { section="" }
  ' "$1" | LC_ALL=C sort
}
expected() {
  unshare -n sh -ec 'nft -f "$1"; nft -s list table inet mxioc_usage' sh "$1" > "$2" || return 1
  normalize "$2" > "$2.norm"
}
expected "$work/old" "$work/old-table" || exit 12
expected "$work/next" "$work/next-table" || exit 12
normalize "$saved" > "$work/saved.norm"
{ cmp -s "$work/saved.norm" "$work/old-table.norm" || cmp -s "$work/saved.norm" "$work/next-table.norm"; } || exit 76
snapshot() {
  nft -s list table inet mxioc_usage > "$work/live" || exit 76
  normalize "$work/live" > "$work/live.norm"
}
snapshot
if ! cmp -s "$work/live.norm" "$work/next-table.norm"; then
  cmp -s "$work/live.norm" "$work/old-table.norm" || exit 76
  for chain in input output; do
    prefix=up
    [ "$chain" = input ] || prefix=down
    nft -a list chain inet mxioc_usage "$chain" |
      awk -v chain="$chain" -v name="${prefix}_$id" '
        NF >= 5 && $(NF-1) == "handle" && $NF ~ /^[0-9]+$/ {
          for (i=1; i<NF-2; i++) {
            if ($i == "counter" && $(i+1) == "name" && ($(i+2) == name || $(i+2) == "\"" name "\""))
              print "delete rule inet mxioc_usage " chain " handle " $NF
          }
        }' > "$work/$chain"
    [ "$(wc -l < "$work/$chain")" -eq 1 ] || exit 76
  done
  cat "$work/input" "$work/output" > "$work/remove"
  printf 'delete counter inet mxioc_usage up_%s\ndelete counter inet mxioc_usage down_%s\n' "$id" "$id" >> "$work/remove"
  nft -c -f "$work/remove"
  snapshot
  cmp -s "$work/live.norm" "$work/old-table.norm" || exit 76
  nft -f "$work/remove"
  snapshot
  cmp -s "$work/live.norm" "$work/next-table.norm" || exit 76
fi
chmod 600 "$work/live"
mv -f -- "$work/live" "$saved"
printf 'MXIOC_LEGACY_METER_CLEARED\n'
`

func (m *Manager) ClearLegacyMeter(ctx context.Context, server string, id, port int) error {
	record, err := m.Record(server)
	if err != nil {
		return err
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		_, err := m.withCore(ctx, server, func(ctx context.Context, _ string, record Record, run coreRunner) (Record, error) {
			return nil, m.clearLegacyMeter(ctx, record, id, port, run)
		})
		return err
	}
	_, err = m.WithPanel(ctx, server, func(panel *Panel, record Record) (any, error) {
		return nil, m.clearLegacyMeter(ctx, record, id, port, panel.run)
	})
	return err
}

func (m *Manager) clearLegacyMeter(ctx context.Context, record Record, id, port int, run coreRunner) error {
	if id < 1 || port < 1 || port > 65535 || value(record["coreUserPending"]) != "" {
		return errors.New("旧计量绑定无效或独立内核操作待核对")
	}
	meters, err := inboundObject(record["meters"])
	if err != nil {
		return err
	}
	cleared, err := inboundObject(record["goMeterCleared"])
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	if _, exists := meters[key]; !exists {
		if value(cleared[key]) == strconv.Itoa(port) {
			return nil
		}
		return errors.New("服务器没有对应的旧计量记录或清理回执，无法核对归属")
	}
	if value(meters[key]) != strconv.Itoa(port) {
		return errors.New("旧计量端口和订阅绑定不一致")
	}
	script, err := clearLegacyMeterScript(meters, id)
	if err != nil {
		return err
	}
	output, err := run(ctx, script, 8<<10)
	if err != nil || strings.TrimSpace(output) != "MXIOC_LEGACY_METER_CLEARED" {
		var code remoteExitError
		if errors.As(err, &code) {
			switch code {
			case 12:
				return errors.New("远端需要 nftables 和临时网络命名空间权限")
			case 75:
				return errors.New("远端正在处理计量规则，请稍后重试")
			case 76:
				return errors.New("远端计量规则与旧记录不一致，清理结果需核对")
			}
		}
		return errors.New("旧计量清理未确认，请重试核对")
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
	delete(meters, key)
	cleared[key] = port
	fresh["meters"], fresh["goMeterCleared"] = meters, cleared
	if err := m.flush(data); err != nil {
		return errors.New("远端旧计量已清理，总控保存待重试")
	}
	return nil
}
