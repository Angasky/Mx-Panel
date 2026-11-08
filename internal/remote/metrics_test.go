package remote

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostSampleScriptOnLinux(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("requires Linux /proc")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "bash", "-s")
	cmd.Stdin = strings.NewReader(hostSampleScript)
	output, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := parseHostSample(string(output), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if raw.view["cores"].(int) < 1 || raw.view["hostname"] == "" {
		t.Fatal("host sample incomplete")
	}
}

const metricFixture = `
__MXIOC_METRIC_stat__
cpu  100 0 50 800 50 0 0 0 99 0
cpu0 100 0 50 800 50 0 0 0 99 0
__MXIOC_METRIC_mem__
MemTotal: 1000 kB
MemAvailable: 600 kB
SwapTotal: 200 kB
SwapFree: 150 kB
__MXIOC_METRIC_net__
Inter-| Receive | Transmit
 face |bytes packets errs drop fifo frame compressed multicast|bytes packets errs drop fifo colls carrier compressed
lo: 900 0 0 0 0 0 0 0 900 0 0 0 0 0 0 0
eth0: 9007199254740993 0 0 0 0 0 0 0 1000 0 0 0 0 0 0 0
docker0: 999 0 0 0 0 0 0 0 999 0 0 0 0 0 0 0
__MXIOC_METRIC_route__
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 00000000 0100000A 0003 0 0 0 00000000 0 0 0
__MXIOC_METRIC_route6__
__MXIOC_METRIC_cpu__
model name : Fixture CPU
__MXIOC_METRIC_uptime__
100.00 80.00
__MXIOC_METRIC_boot__
fixture-boot
__MXIOC_METRIC_load__
0.01 0.02 0.03 1/50 20
__MXIOC_METRIC_hostname__
fixture-host
__MXIOC_METRIC_kernel__
6.1.0
__MXIOC_METRIC_arch__
x86_64
__MXIOC_METRIC_os__
PRETTY_NAME="Debian GNU/Linux"
__MXIOC_METRIC_disks__
Filesystem Type 1-blocks Used Available Capacity Mounted on
/dev/vda1 ext4 10000 4000 5500 43% /
tmpfs tmpfs 1000 0 1000 0% /run
/dev/vda1 ext4 10000 4000 5500 43% /duplicate
/dev/vdb1 ext4 10000 2000 8000 20% /data with spaces
__MXIOC_METRIC_addresses__
[{"ifname":"eth0","addr_info":[{"scope":"global","local":"192.0.2.5","family":"inet","prefixlen":24},{"scope":"link","local":"fe80::1","family":"inet6","prefixlen":64}]}]
__MXIOC_METRIC_end__
`

func parseMetricFixture(t *testing.T, text string) *hostSample {
	t.Helper()
	raw, err := parseHostSample(text, time.Unix(1234, 0))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestMetricsParsingAndDeltas(t *testing.T) {
	before := parseMetricFixture(t, metricFixture)
	warm := deriveHostMetrics(before, nil)
	if warm["cpuPercent"] != nil || warm["warmingUp"] != true {
		t.Fatalf("first sample: %v", warm)
	}
	if before.cpus["cpu"].total != 1000 {
		t.Fatal("guest ticks double counted")
	}
	if len(before.view["addresses"].([]Record)) != 1 || len(before.view["disks"].([]Record)) != 2 {
		t.Fatal("address or disk filtering")
	}
	if before.view["disks"].([]Record)[1]["mount"] != "/data with spaces" {
		t.Fatal("mount spaces")
	}
	next := strings.NewReplacer("100.00 80.00", "105.00 80.00", "100 0 50 800 50", "130 0 50 870 50", "9007199254740993", "9007199254741493", "1000 0 0 0 0 0 0 0", "1500 0 0 0 0 0 0 0").Replace(metricFixture)
	after := parseMetricFixture(t, next)
	view := deriveHostMetrics(after, before)
	if view["cpuPercent"] != float64(30) || view["warmingUp"] != false {
		t.Fatalf("CPU delta: %v", view["cpuPercent"])
	}
	network := view["network"].(Record)
	if network["rxBytes"] != uint64(9007199254741493) || network["rxBytesPerSecond"] != float64(100) || network["txBytesPerSecond"] != float64(100) {
		t.Fatalf("network: %v", network)
	}
	if view["memory"].(Record)["percent"] != float64(40) {
		t.Fatal("memory percentage")
	}
	if _, exists := before.view["interfaces"].([]Record)[0]["rxBytesPerSecond"]; exists {
		t.Fatal("derived view mutated history")
	}
	for _, change := range []func(*hostSample){func(s *hostSample) { s.boot = "reboot" }, func(s *hostSample) { s.uptime = 200 }, func(s *hostSample) { s.uptime = 99 }} {
		raw := parseMetricFixture(t, next)
		change(raw)
		v := deriveHostMetrics(raw, before)
		if v["warmingUp"] != true || v["network"].(Record)["rxBytesPerSecond"] != nil || v["cpuPercent"] != nil {
			t.Fatal("invalid interval fabricated rate")
		}
	}
	reset := parseMetricFixture(t, next)
	reset.view["interfaces"].([]Record)[0]["rxBytes"] = uint64(5)
	reset.cpus["cpu"] = cpuTicks{1, 1}
	v := deriveHostMetrics(reset, before)
	if v["network"].(Record)["rxBytesPerSecond"] != nil || v["cpuPercent"] != nil {
		t.Fatal("counter reset fabricated rate")
	}
}

func TestMetricsRejectBrokenSamples(t *testing.T) {
	for _, text := range []string{
		strings.Replace(metricFixture, "__MXIOC_METRIC_end__", "", 1),
		strings.Replace(metricFixture, "100.00 80.00", "NaN 80.00", 1),
		strings.Replace(metricFixture, "MemAvailable: 600", "MemAvailable: 1600", 1),
		strings.Replace(metricFixture, "9007199254740993", "-1", 1),
		strings.Replace(metricFixture, "cpu  100 0 50", "cpu  18446744073709551615 1 50", 1),
		metricFixture + "\n__MXIOC_METRIC_stat__\n",
	} {
		if _, err := parseHostSample(text, time.Now()); err == nil {
			t.Fatal("accepted malformed sample")
		}
	}
	noOptional := strings.Replace(metricFixture, "[{\"ifname\":\"eth0\",\"addr_info\":[{\"scope\":\"global\",\"local\":\"192.0.2.5\",\"family\":\"inet\",\"prefixlen\":24},{\"scope\":\"link\",\"local\":\"fe80::1\",\"family\":\"inet6\",\"prefixlen\":64}]}]", "", 1)
	if len(parseMetricFixture(t, noOptional).view["addresses"].([]Record)) != 0 {
		t.Fatal("iproute2 optional")
	}
}

func TestMetricsCacheCoalescingFailuresAndIsolation(t *testing.T) {
	h := &hostMonitor{entries: map[[32]byte]*metricEntry{}}
	key := [32]byte{1}
	calls := atomic.Int32{}
	collect := func(context.Context) (*hostSample, error) {
		calls.Add(1)
		return parseMetricFixture(t, metricFixture), nil
	}
	view, err := h.sample(context.Background(), key, collect)
	if err != nil {
		t.Fatal(err)
	}
	view["memory"].(map[string]any)["total"] = 0
	view, err = h.sample(context.Background(), key, collect)
	if err != nil || calls.Load() != 1 || view["memory"].(map[string]any)["total"] != json.Number("1024000") {
		t.Fatal("cache mutated or repeated collection")
	}
	h.entries[key].sampled = time.Now().Add(-10 * time.Second)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		_, _ = h.sample(context.Background(), key, func(context.Context) (*hostSample, error) {
			close(started)
			<-release
			return nil, errors.New("offline")
		})
	}()
	<-started
	view, err = h.sample(context.Background(), key, collect)
	if err != nil || view["stale"] != true || calls.Load() != 1 {
		t.Fatal("inflight collection was repeated")
	}
	close(release)
	<-done
	view, err = h.sample(context.Background(), key, collect)
	if err != nil || view["stale"] != true || !strings.Contains(view["error"].(string), "offline") || calls.Load() != 1 {
		t.Fatal("failure backoff or stale marker missing")
	}
	for i := 0; i < 140; i++ {
		k := [32]byte{byte(i), 2}
		if _, err := h.sample(context.Background(), k, collect); err != nil {
			t.Fatal(err)
		}
	}
	if len(h.entries) != 128 {
		t.Fatal("unbounded monitor cache")
	}
}

func TestMetricsHotplugAndIntervalBoundary(t *testing.T) {
	before := parseMetricFixture(t, metricFixture)
	after := parseMetricFixture(t, metricFixture)
	after.uptime = before.uptime + 60
	after.cpus["cpu1"] = cpuTicks{100, 80}
	after.view["interfaces"] = append(after.view["interfaces"].([]Record), Record{"name": "eth1", "rxBytes": uint64(50), "txBytes": uint64(80)})
	after.view["summaryInterfaces"] = []string{"eth0", "eth1"}
	view := deriveHostMetrics(after, before)
	if view["warmingUp"] != false {
		t.Fatal("60 second boundary must remain valid")
	}
	cpus := view["perCpu"].([]Record)
	if len(cpus) != 2 || cpus[1]["name"] != "cpu1" || cpus[1]["percent"] != nil {
		t.Fatal("hotplug CPU invented delta", cpus)
	}
	nics := view["interfaces"].([]Record)
	if nics[len(nics)-1]["rxBytesPerSecond"] != nil || view["network"].(Record)["rxBytesPerSecond"] != nil {
		t.Fatal("new NIC invented rate")
	}
	if view["network"].(Record)["rxBytes"] != uint64(9007199254741043) {
		t.Fatal("hotplug lost counters")
	}
	after.uptime += .001
	if deriveHostMetrics(after, before)["warmingUp"] != true {
		t.Fatal("expired interval accepted")
	}
	after.uptime = before.uptime
	if deriveHostMetrics(after, before)["warmingUp"] != true {
		t.Fatal("zero interval accepted")
	}
}

func TestMetricsOverflowIsUnknownAndFailureRecovers(t *testing.T) {
	raw := parseMetricFixture(t, metricFixture)
	raw.view["interfaces"] = []Record{
		{"name": "eth0", "rxBytes": uint64(^uint64(0)), "txBytes": uint64(10)},
		{"name": "eth1", "rxBytes": uint64(1), "txBytes": uint64(20)},
	}
	raw.view["summaryInterfaces"] = []string{"eth0", "eth1"}
	net := deriveHostMetrics(raw, nil)["network"].(Record)
	if net["rxBytes"] != nil || net["txBytes"] != uint64(30) {
		t.Fatal("overflow wrapped", net)
	}
	h := &hostMonitor{entries: map[[32]byte]*metricEntry{}}
	key := [32]byte{1}
	calls := 0
	fail := func(context.Context) (*hostSample, error) { calls++; return nil, errors.New("offline") }
	if _, err := h.sample(context.Background(), key, fail); err == nil {
		t.Fatal("first failure hidden")
	}
	if _, err := h.sample(context.Background(), key, fail); err == nil || calls != 1 {
		t.Fatal("failure was not cached")
	}
	h.entries[key].failed = time.Now().Add(-6 * time.Second)
	view, err := h.sample(context.Background(), key, func(context.Context) (*hostSample, error) { return parseMetricFixture(t, metricFixture), nil })
	if err != nil || view["stale"] != false || view["warmingUp"] != true || view["error"] != "" {
		t.Fatal("recovery", view, err)
	}
	if !h.entries[key].failed.IsZero() || h.entries[key].failure != "" {
		t.Fatal("failure not cleared")
	}
}
