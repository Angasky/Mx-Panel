package remote

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Fixed read-only commands. No remote Python, installation, persistent agent,
// eval, or sourcing of /etc/os-release is required.
const hostSampleScript = `set -eu
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

type cpuTicks struct{ total, idle uint64 }
type hostSample struct {
	view   Record
	boot   string
	uptime float64
	cpus   map[string]cpuTicks
}

func finiteNumber(s string) (float64, error) {
	n, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
		return 0, errors.New("监控数值无效")
	}
	return n, nil
}
func byteNumber(s string) (uint64, error) { return strconv.ParseUint(s, 10, 64) }
func roundMetric(n float64) float64       { return math.Round(n*10) / 10 }

func parseHostSample(output string, sampledAt time.Time) (*hostSample, error) {
	sections := map[string]string{}
	section := ""
	for _, line := range strings.Split(output, "\n") {
		if strings.HasPrefix(line, "__MXIOC_METRIC_") && strings.HasSuffix(line, "__") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "__MXIOC_METRIC_"), "__")
			if _, duplicate := sections[section]; duplicate {
				return nil, errors.New("监控分段重复")
			}
			sections[section] = ""
		} else if section != "" {
			sections[section] += line + "\n"
		}
	}
	if _, ok := sections["end"]; !ok {
		return nil, errors.New("监控输出不完整")
	}
	up := strings.Fields(sections["uptime"])
	if len(up) < 1 {
		return nil, errors.New("缺少运行时间")
	}
	uptime, err := finiteNumber(up[0])
	if err != nil {
		return nil, err
	}
	boot := strings.TrimSpace(sections["boot"])
	if boot == "" {
		return nil, errors.New("缺少启动标识")
	}
	cpus := map[string]cpuTicks{}
	for _, line := range strings.Split(sections["stat"], "\n") {
		fields := strings.Fields(line)
		if len(fields) < 1 || !strings.HasPrefix(fields[0], "cpu") {
			continue
		}
		if fields[0] != "cpu" {
			if _, err := strconv.ParseUint(strings.TrimPrefix(fields[0], "cpu"), 10, 32); err != nil {
				continue
			}
		}
		if len(fields) < 5 {
			return nil, errors.New("CPU 计数不完整")
		}
		ticks := cpuTicks{}
		for i := 1; i < len(fields) && i <= 8; i++ {
			n, err := byteNumber(fields[i])
			if err != nil || math.MaxUint64-ticks.total < n {
				return nil, errors.New("CPU 计数无效")
			}
			ticks.total += n
			if i == 4 || i == 5 {
				ticks.idle += n
			}
		}
		cpus[fields[0]] = ticks
	}
	if _, ok := cpus["cpu"]; !ok {
		return nil, errors.New("缺少 CPU 计数")
	}
	mem := map[string]uint64{}
	for _, line := range strings.Split(sections["mem"], "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		n, err := byteNumber(f[1])
		if err != nil || n > math.MaxUint64/1024 {
			return nil, errors.New("内存计数无效")
		}
		mem[strings.TrimSuffix(f[0], ":")] = n * 1024
	}
	if mem["MemTotal"] == 0 {
		return nil, errors.New("缺少内存容量")
	}
	available, ok := mem["MemAvailable"]
	if !ok {
		for _, k := range []string{"MemFree", "Buffers", "Cached"} {
			if math.MaxUint64-available < mem[k] {
				return nil, errors.New("内存计数溢出")
			}
			available += mem[k]
		}
	}
	if available > mem["MemTotal"] || mem["SwapFree"] > mem["SwapTotal"] {
		return nil, errors.New("内存计数范围无效")
	}
	memory := Record{"total": mem["MemTotal"], "available": available, "used": mem["MemTotal"] - available, "swapTotal": mem["SwapTotal"], "swapUsed": mem["SwapTotal"] - mem["SwapFree"]}
	memory["percent"] = roundMetric(float64(mem["MemTotal"]-available) / float64(mem["MemTotal"]) * 100)
	nics := []Record{}
	for _, line := range strings.Split(sections["net"], "\n") {
		name, body, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		name = strings.TrimSpace(name)
		if name == "lo" {
			continue
		}
		f := strings.Fields(body)
		if len(f) < 16 {
			return nil, errors.New("网卡计数不完整")
		}
		rx, e1 := byteNumber(f[0])
		tx, e2 := byteNumber(f[8])
		if e1 != nil || e2 != nil {
			return nil, errors.New("网卡计数无效")
		}
		nics = append(nics, Record{"name": name, "rxBytes": rx, "txBytes": tx})
	}
	selected := map[string]bool{}
	for _, line := range strings.Split(sections["route"], "\n") {
		f := strings.Fields(line)
		if len(f) >= 4 && f[1] == "00000000" {
			flags, e := strconv.ParseUint(f[3], 16, 32)
			if e == nil && flags&1 != 0 {
				selected[f[0]] = true
			}
		}
	}
	for _, line := range strings.Split(sections["route6"], "\n") {
		f := strings.Fields(line)
		if len(f) >= 10 && f[0] == strings.Repeat("0", 32) && f[1] == "00" {
			flags, e := strconv.ParseUint(f[8], 16, 32)
			if e == nil && flags&1 != 0 {
				selected[f[len(f)-1]] = true
			}
		}
	}
	if len(selected) == 0 {
		for _, n := range nics {
			name := n["name"].(string)
			virtual := false
			for _, p := range []string{"veth", "docker", "br-", "tun", "tap"} {
				virtual = virtual || strings.HasPrefix(name, p)
			}
			if !virtual {
				selected[name] = true
			}
		}
	}
	names := []string{}
	for name := range selected {
		if name != "lo" {
			names = append(names, name)
		}
	}
	sort.Strings(names)
	loadFields := strings.Fields(sections["load"])
	if len(loadFields) < 3 {
		return nil, errors.New("缺少系统负载")
	}
	load := []float64{}
	for _, f := range loadFields[:3] {
		n, e := finiteNumber(f)
		if e != nil {
			return nil, e
		}
		load = append(load, n)
	}
	model := strings.TrimSpace(sections["arch"])
	for _, line := range strings.Split(sections["cpu"], "\n") {
		k, v, ok := strings.Cut(line, ":")
		if ok && (strings.TrimSpace(k) == "model name" || strings.TrimSpace(k) == "Hardware") {
			model = strings.TrimSpace(v)
			break
		}
	}
	osName := "Linux"
	for _, line := range strings.Split(sections["os"], "\n") {
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			osName = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"'")
			break
		}
	}
	disks := []Record{}
	devices := map[string]bool{}
	for _, line := range strings.Split(sections["disks"], "\n") {
		f := strings.Fields(line)
		if len(f) < 7 || devices[f[0]] {
			continue
		}
		total, e1 := byteNumber(f[2])
		used, e2 := byteNumber(f[3])
		avail, e3 := byteNumber(f[4])
		if e1 != nil || e2 != nil || e3 != nil || total == 0 || used > total || avail > total {
			continue
		}
		mount := strings.Join(f[6:], " ")
		virtual := false
		for _, fs := range []string{"tmpfs", "devtmpfs", "squashfs", "overlay"} {
			virtual = virtual || f[1] == fs
		}
		if virtual && mount != "/" {
			continue
		}
		devices[f[0]] = true
		disks = append(disks, Record{"mount": mount, "filesystem": f[1], "total": total, "used": used, "available": avail, "percent": roundMetric(float64(used) / float64(total) * 100)})
		if len(disks) >= 32 {
			break
		}
	}
	addresses := []Record{}
	var ipRows []struct {
		Name      string `json:"ifname"`
		Addresses []struct {
			Scope  string `json:"scope"`
			Local  string `json:"local"`
			Family string `json:"family"`
			Prefix int    `json:"prefixlen"`
		} `json:"addr_info"`
	}
	if json.Unmarshal([]byte(sections["addresses"]), &ipRows) == nil {
		for _, nic := range ipRows {
			if nic.Name == "lo" {
				continue
			}
			for _, a := range nic.Addresses {
				if a.Scope == "global" {
					addresses = append(addresses, Record{"interface": nic.Name, "address": a.Local, "family": a.Family, "prefix": a.Prefix})
				}
			}
		}
	}
	return &hostSample{boot: boot, uptime: uptime, cpus: cpus, view: Record{"sampledAt": float64(sampledAt.UnixMilli()) / 1000, "uptime": uptime, "hostname": strings.TrimSpace(sections["hostname"]), "os": osName, "kernel": strings.TrimSpace(sections["kernel"]), "cpuModel": model, "cores": len(cpus) - 1, "load": load, "memory": memory, "interfaces": nics, "summaryInterfaces": names, "addresses": addresses, "disks": disks}}, nil
}

func deriveHostMetrics(raw, previous *hostSample) Record {
	view := Record{}
	for k, v := range raw.view {
		view[k] = v
	}
	elapsed := float64(0)
	if previous != nil && previous.boot == raw.boot {
		elapsed = raw.uptime - previous.uptime
	}
	valid := elapsed > 0 && elapsed <= 60
	view["cpuPercent"] = nil
	perCPU := []Record{}
	names := []string{}
	for name := range raw.cpus {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if names[i] == "cpu" {
			return names[j] != "cpu"
		}
		if names[j] == "cpu" {
			return false
		}
		a, _ := strconv.Atoi(names[i][3:])
		b, _ := strconv.Atoi(names[j][3:])
		return a < b
	})
	for _, name := range names {
		var percent any
		if valid {
			current := raw.cpus[name]
			old, ok := previous.cpus[name]
			if ok && current.total > old.total && current.idle >= old.idle {
				total, idle := current.total-old.total, current.idle-old.idle
				if idle <= total {
					percent = roundMetric(float64(total-idle) / float64(total) * 100)
				}
			}
		}
		if name == "cpu" {
			view["cpuPercent"] = percent
		} else {
			perCPU = append(perCPU, Record{"name": name, "percent": percent})
		}
	}
	view["perCpu"] = perCPU
	oldNICs := map[string]Record{}
	if valid {
		for _, nic := range previous.view["interfaces"].([]Record) {
			oldNICs[nic["name"].(string)] = nic
		}
	}
	nics := []Record{}
	network := Record{"interfaces": raw.view["summaryInterfaces"]}
	selected := map[string]bool{}
	for _, name := range raw.view["summaryInterfaces"].([]string) {
		selected[name] = true
	}
	for _, nic := range raw.view["interfaces"].([]Record) {
		n := Record{}
		for k, v := range nic {
			n[k] = v
		}
		old := oldNICs[n["name"].(string)]
		for _, fields := range [][2]string{{"rxBytes", "rxBytesPerSecond"}, {"txBytes", "txBytesPerSecond"}} {
			n[fields[1]] = nil
			if old != nil {
				now := n[fields[0]].(uint64)
				before := old[fields[0]].(uint64)
				if now >= before {
					n[fields[1]] = roundMetric(float64(now-before) / elapsed)
				}
			}
		}
		nics = append(nics, n)
	}
	for _, field := range []string{"rxBytes", "txBytes", "rxBytesPerSecond", "txBytesPerSecond"} {
		var sum float64
		var bytes uint64
		count := 0
		all := true
		for _, nic := range nics {
			if !selected[nic["name"].(string)] {
				continue
			}
			count++
			switch v := nic[field].(type) {
			case uint64:
				if math.MaxUint64-bytes < v {
					all = false
				} else {
					bytes += v
				}
			case float64:
				sum += v
			default:
				all = false
			}
		}
		network[field] = nil
		if count > 0 && all {
			if strings.HasSuffix(field, "PerSecond") {
				network[field] = sum
			} else {
				network[field] = bytes
			}
		}
	}
	view["interfaces"] = nics
	view["network"] = network
	view["warmingUp"] = !valid
	view["stale"] = false
	view["error"] = ""
	return view
}

type metricEntry struct {
	raw             *hostSample
	encoded         []byte
	sampled, failed time.Time
	failure         string
	busy            bool
}
type hostMonitor struct {
	mu      sync.Mutex
	entries map[[32]byte]*metricEntry
}

// Metrics keeps a bounded cache and coalesces simultaneous requests. A failed
// sample never turns historical rates into apparently live zeroes.
func (m *Manager) Metrics(ctx context.Context, id string) (Record, error) {
	record, err := m.Record(id)
	if err != nil {
		return nil, err
	}
	password, err := m.Secret(record, "sshPassword")
	if err != nil {
		return nil, err
	}
	port, err := parsedPort(record["sshPort"], 22)
	if err != nil {
		return nil, err
	}
	connection := Connection{Host: value(record["host"]), Port: port, User: value(record["sshUser"]), Password: password, Fingerprint: value(record["fingerprint"])}
	keyData, _ := json.Marshal([]any{id, connection.Host, port, connection.User, connection.Password, connection.Fingerprint, record["name"]})
	key := sha256.Sum256(keyData)
	m.mu.Lock()
	if m.monitor == nil {
		m.monitor = &hostMonitor{entries: map[[32]byte]*metricEntry{}}
	}
	monitor := m.monitor
	m.mu.Unlock()
	return monitor.sample(ctx, key, func(ctx context.Context) (*hostSample, error) {
		output, e := Execute(ctx, connection, hostSampleScript, 512<<10)
		if e != nil {
			return nil, e
		}
		raw, e := parseHostSample(output, time.Now())
		if e == nil {
			raw.view["serverId"] = id
			raw.view["name"] = record["name"]
			raw.view["managementIp"] = connection.Host
		}
		return raw, e
	})
}
func metricView(entry *metricEntry, stale bool, message string) (Record, error) {
	if len(entry.encoded) == 0 {
		return nil, errors.New(message)
	}
	var view Record
	decoder := json.NewDecoder(strings.NewReader(string(entry.encoded)))
	decoder.UseNumber()
	if err := decoder.Decode(&view); err != nil {
		return nil, err
	}
	if stale {
		view["stale"] = true
		view["error"] = message
	}
	return view, nil
}
func (h *hostMonitor) sample(ctx context.Context, key [32]byte, collect func(context.Context) (*hostSample, error)) (Record, error) {
	h.mu.Lock()
	entry := h.entries[key]
	if entry == nil {
		if len(h.entries) >= 128 {
			var oldestKey [32]byte
			var oldest *metricEntry
			for k, e := range h.entries {
				if !e.busy && (oldest == nil || e.sampled.Before(oldest.sampled)) {
					oldestKey, oldest = k, e
				}
			}
			if oldest == nil {
				h.mu.Unlock()
				return nil, errors.New("监控采样繁忙，请稍后重试")
			}
			delete(h.entries, oldestKey)
		}
		entry = &metricEntry{}
		h.entries[key] = entry
	}
	if time.Since(entry.sampled) < 5*time.Second {
		view, err := metricView(entry, false, "")
		h.mu.Unlock()
		return view, err
	}
	if time.Since(entry.failed) < 5*time.Second {
		view, err := metricView(entry, true, entry.failure)
		h.mu.Unlock()
		return view, err
	}
	if entry.busy {
		view, err := metricView(entry, true, "正在采集该服务器，请稍后重试")
		h.mu.Unlock()
		return view, err
	}
	entry.busy = true
	previous := entry.raw
	h.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	raw, err := collect(ctx)
	h.mu.Lock()
	defer h.mu.Unlock()
	entry.busy = false
	if err != nil {
		entry.failed = time.Now()
		entry.failure = fmt.Sprintf("硬件采样失败：%.200s", err.Error())
		return metricView(entry, true, entry.failure)
	}
	view := deriveHostMetrics(raw, previous)
	encoded, err := json.Marshal(view)
	if err != nil {
		return nil, err
	}
	entry.raw = raw
	entry.encoded = encoded
	entry.sampled = time.Now()
	entry.failed = time.Time{}
	entry.failure = ""
	return metricView(entry, false, "")
}
