// Package hostsample collects fixed read-only Linux observations independently of the panel.
package hostsample

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"sync"
	"time"
)

const Script = `set -eu
export LC_ALL=C
part() { printf '\n__MXIOC_METRIC_%s__\n' "$1"; }
part stat; cat /proc/stat
part mem; cat /proc/meminfo
part net; cat /proc/net/dev
part route; cat /proc/net/route 2>/dev/null || true
part route6; cat /proc/net/ipv6_route 2>/dev/null || true
part cpu; cat /proc/cpuinfo
part uptime; cat /proc/uptime
part boot; cat /proc/sys/kernel/random/boot_id
part load; cat /proc/loadavg
part hostname; hostname
part kernel; uname -r
part arch; uname -m
part os; cat /etc/os-release 2>/dev/null || true
part disks; df -P -T -B1 -l 2>/dev/null || true
part addresses; ip -j address show 2>/dev/null || true
part end
`

type bounded struct {
	mu       sync.Mutex
	data     []byte
	overflow bool
}

func (b *bounded) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := (512 << 10) - len(b.data)
	if len(p) > remaining {
		p = p[:remaining]
		b.overflow = true
	}
	b.data = append(b.data, p...)
	return n, nil
}
func Collect(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = strings.NewReader(Script)
	output := &bounded{}
	cmd.Stdout = output
	cmd.Stderr = output
	if e := cmd.Run(); e != nil {
		return "", errors.New("本机资源采样失败")
	}
	if output.overflow {
		return "", errors.New("采样超出大小限制")
	}
	return string(output.data), nil
}
