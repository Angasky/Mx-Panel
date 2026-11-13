package remote

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"

	"github.com/Angasky/dingzhi-ban/internal/netguard"
)

type sniTarget struct{ domain, address string }

func sniProbeKernelScript(kind string) string {
	script := `command -v curl >/dev/null && command -v timeout >/dev/null || { printf 'MXIOC_REALITY_ERROR tools\n'; exit 0; }
binary=''
for candidate in /usr/local/x-ui/bin/xray* /usr/local/bin/xray; do
 if test -f "$candidate" && test -x "$candidate"; then binary="$candidate"; break; fi
done
test -n "$binary" || { printf 'MXIOC_REALITY_ERROR kernel\n'; exit 0; }
server_binary="$binary"; server_flag='-config'; server_config='stdin:'
`
	if kind == "sing-box" {
		script += `server_binary=''
for candidate in /usr/bin/sing-box /usr/local/bin/sing-box /etc/sing-box/sing-box; do
 if test -f "$candidate" && test -x "$candidate"; then server_binary="$candidate"; break; fi
done
test -n "$server_binary" || { printf 'MXIOC_REALITY_ERROR kernel\n'; exit 0; }
server_flag='-c'; server_config='/dev/stdin'
`
	}
	return script
}

func sniProbeMessage(kind, code string) string {
	switch code {
	case "tools":
		return "服务器缺少 curl 或 timeout"
	case "kernel":
		if kind == "sing-box" {
			return "服务器未安装可用的 sing-box 或 Xray 验证内核"
		}
		return "服务器未安装可用的 Xray 验证内核"
	case "startup":
		return "隔离测试内核启动失败，请重试扫描"
	case "ports":
		return "随机测试端口已占用，请重试扫描"
	}
	return "隔离 Reality 验证未完成，请重试"
}

// Ephemeral Xray pair, loopback listeners only; no production configuration,
// user, nft counter, or proxy port is read or changed.
func realityProbeScript(targets []sniTarget) (string, error) {
	return realityProbeScriptForCore("xray", targets)
}

// sing-box has no HTTP blackhole response, so its only outbound is a loopback
// SOCKS sink in the temporary Xray process. A 403 then proves Reality transport
// plus authenticated forwarding, without dialing the requested HTTP destination.
func realityProbeScriptForCore(kind string, targets []sniTarget) (string, error) {
	if kind != "sing-box" {
		kind = "xray"
	}
	if len(targets) == 0 || len(targets) > 20 {
		return "", errors.New("Reality 每批支持 1–20 个目标")
	}
	ports := []int{}
	used := map[int]bool{}
	count := 2 * len(targets)
	if kind == "sing-box" {
		count++ // An isolated Xray SOCKS/HTTP-blackhole sink confirms the sing-box data path.
	}
	for len(ports) < count {
		n, err := rand.Int(rand.Reader, big.NewInt(45535))
		if err != nil {
			return "", err
		}
		port := 20001 + int(n.Int64())
		if !used[port] {
			used[port] = true
			ports = append(ports, port)
		}
	}
	server := Record{"log": Record{"loglevel": "none"}, "inbounds": []any{}, "outbounds": []any{Record{"protocol": "blackhole", "settings": Record{"response": Record{"type": "http"}}}}}
	client := Record{"log": Record{"loglevel": "none"}, "inbounds": []any{}, "outbounds": []any{}, "routing": Record{"rules": []any{}}}
	jobs := []string{}
	socksPorts := []string{}
	portHex := " "
	if kind == "sing-box" {
		sink := ports[len(ports)-1]
		server = Record{"log": Record{"disabled": true}, "inbounds": []any{}, "outbounds": []any{Record{"type": "socks", "tag": "proof-sink", "server": "127.0.0.1", "server_port": sink, "version": "5"}}}
		client["inbounds"] = []any{Record{"tag": "proof-sink", "listen": "127.0.0.1", "port": sink, "protocol": "socks", "settings": Record{"auth": "noauth"}}}
		client["outbounds"] = []any{Record{"tag": "proof-sink", "protocol": "blackhole", "settings": Record{"response": Record{"type": "http"}}}}
		client["routing"].(Record)["rules"] = []any{Record{"type": "field", "inboundTag": []any{"proof-sink"}, "outboundTag": "proof-sink"}}
		portHex += fmt.Sprintf("%04X ", sink)
		socksPorts = append(socksPorts, fmt.Sprint(sink))
	}
	for i, target := range targets {
		domain, err := certificateDomain(target.domain)
		if err != nil {
			return "", err
		}
		ip, err := netip.ParseAddr(target.address)
		if err != nil || !netguard.PublicAddress(ip) {
			return "", errors.New("Reality 目标必须是已核验的公网 IP")
		}
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return "", err
		}
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return "", err
		}
		id[6] = (id[6] & 15) | 64
		id[8] = (id[8] & 63) | 128
		uuid := fmt.Sprintf("%x-%x-%x-%x-%x", id[:4], id[4:6], id[6:8], id[8:10], id[10:])
		sid := make([]byte, 8)
		if _, err = rand.Read(sid); err != nil {
			return "", err
		}
		short := hex.EncodeToString(sid)
		stream := Record{"network": "tcp", "security": "reality", "realitySettings": Record{"target": net.JoinHostPort(ip.Unmap().String(), "443"), "serverNames": []any{domain}, "privateKey": base64.RawURLEncoding.EncodeToString(private.Bytes()), "shortIds": []any{short}, "minClientVer": "1.8.2"}}
		inbound := Record{"tag": fmt.Sprintf("probe-server-%d", i), "listen": "127.0.0.1", "port": ports[2*i], "protocol": "vless", "settings": Record{"clients": []any{Record{"id": uuid, "flow": "xtls-rprx-vision"}}, "decryption": "none"}, "streamSettings": stream}
		if kind == "sing-box" {
			inbound, err = legacyNativeInbound(kind, inbound)
			if err != nil {
				return "", err
			}
		}
		server["inbounds"] = append(server["inbounds"].([]any), inbound)
		inTag, outTag := fmt.Sprintf("probe-in-%d", i), fmt.Sprintf("probe-out-%d", i)
		client["inbounds"] = append(client["inbounds"].([]any), Record{"tag": inTag, "listen": "127.0.0.1", "port": ports[2*i+1], "protocol": "socks", "settings": Record{"auth": "noauth"}})
		user := Record{"id": uuid, "encryption": "none", "flow": "xtls-rprx-vision"}
		destination := Record{"address": "127.0.0.1", "port": ports[2*i], "users": []any{user}}
		client["outbounds"] = append(client["outbounds"].([]any), Record{"tag": outTag, "protocol": "vless", "settings": Record{"vnext": []any{destination}}, "streamSettings": Record{"network": "tcp", "security": "reality", "realitySettings": Record{"serverName": domain, "fingerprint": "chrome", "publicKey": base64.RawURLEncoding.EncodeToString(private.PublicKey().Bytes()), "shortId": short}}})
		routing := client["routing"].(Record)
		routing["rules"] = append(routing["rules"].([]any), Record{"type": "field", "inboundTag": []any{inTag}, "outboundTag": outTag})
		for _, port := range ports[2*i : 2*i+2] {
			portHex += fmt.Sprintf("%04X ", port)
		}
		socksPorts = append(socksPorts, fmt.Sprint(ports[2*i+1]))
		if i%4 == 0 {
			jobs = append(jobs, "pids=''\n")
		}
		jobs = append(jobs, fmt.Sprintf("probe %d %d &\npids=\"$pids $!\"\n", i, ports[2*i+1]))
		if i%4 == 3 || i == len(targets)-1 {
			jobs = append(jobs, "for pid in $pids; do wait \"$pid\" || true; done\npids=''\n")
		}
	}
	s, _ := json.Marshal(server)
	c, _ := json.Marshal(client)
	script := `set -eu
__KERNELS__
ports_hex=__PORTS__
for table in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
 test -r "$table" || continue
 while read -r entry_id bind_address peer_address bind_state rest; do
  case "$ports_hex" in *" ${bind_address##*:} "*) printf 'MXIOC_REALITY_ERROR ports\n'; exit 0;; esac
 done < "$table"
done
server_pid=''; client_pid=''; pids=''
cleanup() {
 for pid in $pids; do kill "$pid" 2>/dev/null || true; done
 test -z "$client_pid" || kill "$client_pid" 2>/dev/null || true
 test -z "$server_pid" || kill "$server_pid" 2>/dev/null || true
 wait 2>/dev/null || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM HUP
timeout 75 "$server_binary" run "$server_flag" "$server_config" <<'MXIOC_TEST_SERVER' >/dev/null 2>&1 &
__SERVER__
MXIOC_TEST_SERVER
server_pid=$!
timeout 75 "$binary" run -config stdin: <<'MXIOC_TEST_CLIENT' >/dev/null 2>&1 &
__CLIENT__
MXIOC_TEST_CLIENT
client_pid=$!
ready=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
 kill -0 "$server_pid" 2>/dev/null && kill -0 "$client_pid" 2>/dev/null || { printf 'MXIOC_REALITY_ERROR startup\n'; exit 0; }
 ready=1
 for port in __READY__; do
  if ! (echo > /dev/tcp/127.0.0.1/$port) 2>/dev/null; then ready=0; break; fi
 done
 if test "$ready" = 1; then break; fi
 sleep 0.1
done
test "$ready" = 1 || { printf 'MXIOC_REALITY_ERROR startup\n'; exit 0; }
probe() {
 index="$1"; port="$2"
 for attempt in 1 2; do
  kill -0 "$server_pid" 2>/dev/null && kill -0 "$client_pid" 2>/dev/null || { printf 'MXIOC_REALITY_RESULT %s FAIL\n' "$index"; return; }
  result=$(curl --disable --noproxy '' --socks5-hostname "127.0.0.1:$port" --silent --head --output /dev/null --connect-timeout 4 --max-time 6 --write-out '%{http_code}' http://reality-probe.invalid/) || { printf 'MXIOC_REALITY_RESULT %s FAIL\n' "$index"; return; }
  if test "$result" != 403; then printf 'MXIOC_REALITY_RESULT %s FAIL\n' "$index"; return; fi
 done
 printf 'MXIOC_REALITY_RESULT %s OK\n' "$index"
}
__JOBS__`
	return strings.NewReplacer("__KERNELS__", sniProbeKernelScript(kind), "__PORTS__", quote(portHex), "__SERVER__", string(s), "__CLIENT__", string(c), "__READY__", strings.Join(socksPorts, " "), "__JOBS__", strings.Join(jobs, "")).Replace(script), nil
}
