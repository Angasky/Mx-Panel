package remote

import (
	"context"
	"encoding/base64"
	"errors"
	"maps"
	"strconv"
	"strings"
)

func bandwidthProtocols(row Record) ([]any, error) {
	switch row["protocol"] {
	case "hysteria", "hysteria2", "tuic":
		return []any{"udp"}, nil
	case "shadowsocks", "socks":
		return []any{"tcp", "udp"}, nil
	case "vless", "vmess", "trojan", "http":
		stream, err := inboundObject(row["streamSettings"])
		if err != nil {
			return nil, err
		}
		switch value(stream["network"]) {
		case "", "tcp", "raw", "ws", "grpc", "httpupgrade", "xhttp":
			return []any{"tcp"}, nil
		case "kcp", "quic":
			return []any{"udp"}, nil
		}
	}
	return nil, errors.New("此入站协议或传输尚未适配端口限速")
}

func (m *Manager) SetLegacyBandwidth(ctx context.Context, server string, id, port, up, down int, identityHash string) error {
	record, err := m.Record(server)
	if err != nil {
		return err
	}
	check := func(record, row Record, run coreRunner) error {
		if len(identityHash) != 64 || row == nil || row["enable"] == false || value(row["port"]) != strconv.Itoa(port) {
			return errors.New("旧入站缺失、停用或身份不完整")
		}
		hash, err := LegacyInboundIdentity(row)
		if err != nil || hash != identityHash {
			return errors.New("旧入站身份已变化，请刷新核对")
		}
		settings, err := inboundObject(row["settings"])
		if err != nil {
			return err
		}
		clients, ok := settings["clients"].([]any)
		if !ok || len(clients) != 1 {
			return errors.New("只有独占单用户入站支持端口限速")
		}
		protocols, err := bandwidthProtocols(row)
		if err != nil {
			return err
		}
		for _, protocol := range protocols {
			if protocol == "tcp" && (value(record["sshPort"]) == strconv.Itoa(port) || value(record["panelPort"]) == strconv.Itoa(port)) {
				return errors.New("节点端口与管理端口重合")
			}
		}
		return m.applyLegacyBandwidth(ctx, record, id, Record{"port": port, "protocols": protocols, "uploadKbps": up, "downloadKbps": down}, run)
	}
	if _, err := corePath(value(record["installType"])); err == nil {
		_, err := m.withCore(ctx, server, func(ctx context.Context, kind string, record Record, run coreRunner) (Record, error) {
			if value(record["coreUserPending"]) != "" {
				return nil, errors.New("独立内核操作待核对，请先完成原操作")
			}
			saved, err := m.Secret(record, "coreState")
			if err != nil {
				return nil, err
			}
			_, doc, err := readCore(ctx, kind, run)
			if err != nil {
				return nil, err
			}
			inventory, err := coreInventory(kind, record, doc, saved)
			if err != nil {
				return nil, err
			}
			state, err := parseLegacyCoreState(saved)
			if err != nil {
				return nil, err
			}
			tag := "mxioc-inbound-" + strconv.Itoa(id)
			for _, row := range anyRecords(doc["inbounds"]) {
				if row["tag"] != tag && (value(row["port"]) == strconv.Itoa(port) || value(row["listen_port"]) == strconv.Itoa(port)) {
					return nil, errors.New("此端口仍有其他入站使用")
				}
			}
			for i, row := range anyRecords(inventory["inbounds"]) {
				if row["id"] == id && row["coreStatus"] == "present" {
					return nil, check(record, state.Inbounds[i], run)
				}
			}
			return nil, errors.New("独立内核入站尚未核对")
		})
		return err
	}
	_, err = m.WithPanel(ctx, server, func(panel *Panel, record Record) (any, error) {
		rows, err := creationRows(ctx, panel)
		if err != nil {
			return nil, err
		}
		var target Record
		for _, row := range rows {
			if value(row["id"]) == strconv.Itoa(id) {
				target = row
			} else if value(row["port"]) == strconv.Itoa(port) {
				return nil, errors.New("此端口仍有其他入站使用")
			}
		}
		panelPort := panel.base.Port()
		if panelPort == "" {
			panelPort = "80"
			if panel.base.Scheme == "https" {
				panelPort = "443"
			}
		}
		record = maps.Clone(record)
		record["panelPort"] = panelPort
		return nil, check(record, target, panel.run)
	})
	return err
}

func (m *Manager) applyLegacyBandwidth(ctx context.Context, record Record, id int, policy Record, run coreRunner) error {
	policies, err := inboundObject(record["bandwidths"])
	if err != nil {
		return err
	}
	key := strconv.Itoa(id)
	if existing, ok := policies[key].(Record); ok && value(existing["port"]) != value(policy["port"]) {
		return errors.New("已有旧规则关联其他端口，请先核对并清理")
	}
	for other, raw := range policies {
		row, _ := raw.(Record)
		if other != key && value(row["port"]) == value(policy["port"]) {
			return errors.New("此端口已有其他限速记录")
		}
	}
	previous, err := legacyBandwidthRules(policies)
	if err != nil {
		return err
	}
	nextPolicies := maps.Clone(policies)
	nextPolicies[key] = policy
	next, err := legacyBandwidthRules(nextPolicies)
	if err != nil {
		return err
	}
	encode := func(s string) string { return quote(base64.StdEncoding.EncodeToString([]byte(s))) }
	fresh := "0"
	if len(policies) == 0 {
		fresh = "1"
	}
	script := "set -Eeuo pipefail\nold=" + encode(previous) + "\nnext=" + encode(next) + "\nfresh=" + fresh + "\n" + legacyBandwidthApply
	output, err := run(ctx, script, 8<<10)
	if err != nil || strings.TrimSpace(output) != "MXIOC_LEGACY_BANDWIDTH_APPLIED" {
		var code remoteExitError
		if errors.As(err, &code) {
			switch code {
			case 12:
				return errors.New("远端需要 nftables、systemd 和临时网络命名空间权限")
			case 75:
				return errors.New("远端正在处理限速规则，请稍后重试")
			case 76:
				return errors.New("远端限速规则与总控记录不一致，已停止覆盖")
			}
		}
		return errors.New("远端限速未确认，请使用相同的设置重试")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	data, err := m.load()
	if err != nil {
		return err
	}
	stored, err := find(data, value(record["id"]))
	if err != nil {
		return err
	}
	stored["bandwidths"] = nextPolicies
	if cleared, ok := stored["goBandwidthCleared"].(Record); ok {
		delete(cleared, key)
	}
	if err := m.flush(data); err != nil {
		return errors.New("远端限速已应用，总控记录待重试")
	}
	return nil
}

const legacyBandwidthApply = `
command -v nft >/dev/null && command -v unshare >/dev/null && command -v systemctl >/dev/null || exit 12
exec 9>/var/lock/mxioc-bandwidth.lock
flock -n 9 || exit 75
dir=/etc/mxioc-bandwidth
saved="$dir/rules.nft"
unit=/etc/systemd/system/mxioc-bandwidth-restore.service
[ ! -L "$dir" ] && [ ! -L "$saved" ] && [ ! -L "$unit" ] || exit 76
work=$(mktemp -d)
trap 'rm -rf -- "$work"; if [ -n "${staged:-}" ]; then rm -f -- "$staged"; fi' EXIT
printf '%s' "$old" | base64 -d > "$work/old"
printf '%s' "$next" | base64 -d > "$work/next"
cat > "$work/unit" <<'UNIT'
[Unit]
Description=Restore MXIOC dedicated inbound bandwidth limits
After=nftables.service network-pre.target
Before=xray.service sing-box.service x-ui.service
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/bin/sh -c 'nft list table inet mxioc_bandwidth >/dev/null 2>&1 || nft -f /etc/mxioc-bandwidth/rules.nft'
[Install]
WantedBy=multi-user.target
UNIT
if [ -e "$unit" ]; then
  [ -f "$unit" ] && cmp -s "$unit" "$work/unit" || exit 76
else
  [ "$fresh" = 1 ] || exit 76
fi
if [ -e "$saved" ]; then
  [ -f "$saved" ] && { cmp -s "$saved" "$work/old" || cmp -s "$saved" "$work/next"; } || exit 76
else
  [ "$fresh" = 1 ] || exit 76
fi
canonicalize() {
  unshare -n sh -ec 'nft -f "$1"; nft -s list table inet mxioc_bandwidth' sh "$1"
}
canonicalize "$work/old" > "$work/old-live" || exit 12
canonicalize "$work/next" > "$work/next-live" || exit 12
nft list tables > "$work/tables"
if grep -Fxq 'table inet mxioc_bandwidth' "$work/tables"; then
  [ -f "$saved" ] || exit 76
  nft -s list table inet mxioc_bandwidth > "$work/live"
  { cmp -s "$work/live" "$work/old-live" || cmp -s "$work/live" "$work/next-live"; } || exit 76
  printf 'delete table inet mxioc_bandwidth\n' > "$work/transaction"
else
  [ "$fresh" = 1 ] || exit 76
  : > "$work/live"
  : > "$work/transaction"
fi
cat "$work/next" >> "$work/transaction"
nft -c -f "$work/transaction"
mkdir -p -- "$dir"
if [ ! -f "$unit" ]; then
  install -m 0644 "$work/unit" "$unit"
fi
if [ ! -f "$saved" ]; then
  staged=$(mktemp "$dir/.apply.XXXXXXXX")
  install -m 0600 "$work/old" "$staged"
  mv -f -- "$staged" "$saved"
fi
systemctl daemon-reload
systemctl enable mxioc-bandwidth-restore.service >/dev/null 2>&1
staged=$(mktemp "$dir/.apply.XXXXXXXX")
install -m 0600 "$work/next" "$staged"
if ! cmp -s "$work/live" "$work/next-live"; then
  nft -f "$work/transaction"
fi
nft -s list table inet mxioc_bandwidth > "$work/live"
cmp -s "$work/live" "$work/next-live" || exit 76
mv -f -- "$staged" "$saved"
printf 'MXIOC_LEGACY_BANDWIDTH_APPLIED\n'
`
