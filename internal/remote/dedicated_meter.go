package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"
)

func dedicatedMeterScript(meters Record, id, port int) (string, error) {
	if id < 1 || port < 1 || port > 65535 {
		return "", errors.New("专属计量目标无效")
	}
	next := maps.Clone(meters)
	key := strconv.Itoa(id)
	if old, exists := next[key]; exists && value(old) != strconv.Itoa(port) {
		return "", errors.New("计量端口变化")
	}
	for target, raw := range next {
		if target != key && value(raw) == strconv.Itoa(port) {
			return "", errors.New("计量端口被其他入站使用")
		}
	}
	next[key] = port
	oldRules, err := legacyMeterRules(meters)
	if err != nil {
		return "", err
	}
	nextRules, err := legacyMeterRules(next)
	if err != nil {
		return "", err
	}
	addition := fmt.Sprintf("add counter inet mxioc_usage up_%d\nadd counter inet mxioc_usage down_%d\nadd rule inet mxioc_usage input meta l4proto { tcp, udp } th dport %d counter name up_%d\nadd rule inet mxioc_usage output meta l4proto { tcp, udp } th sport %d counter name down_%d\n", id, id, port, id, port, id)
	encode := func(s string) string { return quote(base64.StdEncoding.EncodeToString([]byte(s))) }
	return "set -Eeuo pipefail\nold=" + encode(oldRules) + "\nnext=" + encode(nextRules) + "\naddition=" + encode(addition) + "\nempty=" + strconv.FormatBool(len(meters) == 0) + "\n" + dedicatedMeterSetup, nil
}

const dedicatedMeterSetup = `
command -v nft >/dev/null && command -v unshare >/dev/null || exit 12
exec 8>/var/lock/mxioc-meter.lock
flock -n 8 || exit 75
dir=/etc/mxioc-meter
[ ! -L "$dir" ] || exit 76
install -d -m 700 "$dir"
saved="$dir/rules.nft"
[ ! -L "$saved" ] || exit 76
work=$(mktemp -d "$dir/.add.XXXXXXXX")
trap 'rm -rf -- "$work"' EXIT
printf '%s' "$old" | base64 -d > "$work/old"
printf '%s' "$next" | base64 -d > "$work/next"
printf '%s' "$addition" | base64 -d > "$work/add"
normalize() {
 awk '{sub(/^[[:space:]]+/, "");sub(/[[:space:]]+$/, "")} /^chain (input|output) \{$/ {section=$2} NF {print section ":" $0} /^}$/ {section=""}' "$1" | LC_ALL=C sort
}
expected() {
 unshare -n sh -ec 'nft -f "$1"; nft -s list table inet mxioc_usage' sh "$1" > "$2"
 normalize "$2" > "$2.norm"
}
expected "$work/old" "$work/old-table"
expected "$work/next" "$work/next-table"
if [ -f "$saved" ]; then
 normalize "$saved" > "$work/saved.norm"
 { cmp -s "$work/saved.norm" "$work/old-table.norm" || cmp -s "$work/saved.norm" "$work/next-table.norm"; } || exit 76
fi
if nft -s list table inet mxioc_usage > "$work/live" 2>/dev/null; then
 normalize "$work/live" > "$work/live.norm"
 if ! cmp -s "$work/live.norm" "$work/next-table.norm"; then
  cmp -s "$work/live.norm" "$work/old-table.norm" || exit 76
  nft -c -f "$work/add"
  nft -f "$work/add"
 fi
else
 [ "$empty" = true ] || exit 76
 nft -c -f "$work/next"
 nft -f "$work/next"
fi
nft -s list table inet mxioc_usage > "$work/live"
normalize "$work/live" > "$work/live.norm"
cmp -s "$work/live.norm" "$work/next-table.norm" || exit 76
chmod 600 "$work/live"
mv -f -- "$work/live" "$saved"
unit=/etc/systemd/system/mxioc-meter-restore.service
[ ! -L "$unit" ] || exit 76
cat > "$work/unit" <<'UNIT'
[Unit]
Description=Restore MXIOC dedicated inbound accounting rules
Before=xray.service sing-box.service
After=nftables.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft list table inet mxioc_usage >/dev/null 2>&1 || nft -f /etc/mxioc-meter/rules.nft'
[Install]
WantedBy=multi-user.target
UNIT
if [ -e "$unit" ]; then cmp -s "$unit" "$work/unit" || exit 76; fi
install -m 644 "$work/unit" "$unit"
systemctl daemon-reload
systemctl enable mxioc-meter-restore.service
printf 'MXIOC_DEDICATED_METER_READY\n'
`

func (m *Manager) ensureDedicatedMeter(ctx context.Context, record Record, id, port int, run coreRunner) error {
	meters, err := inboundObject(record["meters"])
	if err != nil {
		return err
	}
	script, err := dedicatedMeterScript(meters, id, port)
	if err != nil {
		return err
	}
	output, err := run(ctx, script, 8<<10)
	if err != nil || !strings.Contains(output, "MXIOC_DEDICATED_METER_READY") {
		return errors.New("专属端口计量初始化或规则核对失败，保留归属待重试")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	current, err := find(data, value(record["id"]))
	if err != nil {
		return err
	}
	latest, err := inboundObject(current["meters"])
	if err != nil {
		return err
	}
	a, _ := identity(meters)
	b, _ := identity(latest)
	if a != b {
		return errors.New("计量登记已变化")
	}
	latest[strconv.Itoa(id)] = port
	current["meters"] = latest
	return m.flush(data)
}
func readDedicatedMeter(ctx context.Context, id int, run coreRunner) (Record, error) {
	raw, err := run(ctx, "nft -j list table inet mxioc_usage", 2<<20)
	if err != nil {
		return nil, errors.New("专属端口计数无法读取")
	}
	var data struct {
		NFTables []struct {
			Counter struct {
				Family, Table, Name string
				Bytes               json.Number
			} `json:"counter"`
		} `json:"nftables"`
	}
	if json.Unmarshal([]byte(raw), &data) != nil {
		return nil, errors.New("专属计量 JSON 无效")
	}
	result := Record{"source": "inbound"}
	for _, entry := range data.NFTables {
		c := entry.Counter
		for _, direction := range []string{"up", "down"} {
			if c.Name != direction+"_"+strconv.Itoa(id) {
				continue
			}
			if c.Family != "inet" || c.Table != "mxioc_usage" || result[direction] != nil {
				return nil, errors.New("专属计数重复或归属异常")
			}
			n, err := strconv.ParseInt(string(c.Bytes), 10, 64)
			if err != nil || n < 0 {
				return nil, errors.New("专属计数缺失或无效")
			}
			result[direction] = n
		}
	}
	if result["up"] == nil || result["down"] == nil {
		return nil, errors.New("专属计数不完整，不能视为零")
	}
	return result, nil
}
