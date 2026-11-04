package subscriptions

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestXrayHAPythonCompatibilityAndStrictPriority(t *testing.T) {
	raw, err := os.ReadFile("testdata/xray-ha-python.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Nodes    []Record
		Expected Record
	}
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err = decoder.Decode(&fixture); err != nil {
		t.Fatal(err)
	}
	actual, err := xrayFailover(Record{"name": "fixture"}, fixture.Nodes, 30)
	if err != nil {
		t.Fatal(err)
	}
	// Modern Xray removed allowInsecure, including explicit false. Omitting
	// false retains certificate verification while accepting the current schema.
	for _, v := range fixture.Expected["outbounds"].([]any) {
		out := v.(Record)
		stream, _ := out["streamSettings"].(Record)
		tls, _ := stream["tlsSettings"].(Record)
		if tls["allowInsecure"] == false {
			delete(tls, "allowInsecure")
		}
	}
	got, _ := json.Marshal(actual)
	want, _ := json.Marshal(fixture.Expected)
	if string(got) != string(want) {
		t.Fatalf("Python compatibility changed\n%s\n%s", got, want)
	}
	balancers := actual["routing"].(Record)["balancers"].([]any)
	if len(balancers) != 6 {
		t.Fatal("lost a path")
	}
	for i, v := range balancers {
		b := v.(Record)
		if len(b["selector"].([]any)) != 1 {
			t.Fatal("priority became load balancing")
		}
		if i == 5 && b["fallbackTag"] != "mx-reject" {
			t.Fatal("last fallback is not reject")
		}
	}
	checkXrayHAConfig(t, got)
}

func TestXrayHAMixedNativeEntrances(t *testing.T) {
	doc, err := xrayFailover(Record{"name": "mixed"}, []Record{
		{"name": "xray", "type": "vless", "server": "one.example.net", "port": 24001, "uuid": "11111111-1111-4111-8111-111111111111",
			"tls": true, "servername": "www.example.net", "client-fingerprint": "chrome", "flow": "xtls-rprx-vision",
			"reality-opts": Record{"public-key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", "short-id": "abcd", "support-x25519mlkem768": true}},
		{"name": "sing-box", "type": "vmess", "server": "two.example.net", "port": 24002,
			"uuid": "22222222-2222-4222-8222-222222222222", "cipher": "auto", "alterId": 0},
	}, 30)
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	checkXrayHAConfig(t, data)
}

func checkXrayHAConfig(t *testing.T, raw []byte) {
	t.Helper()
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
		cmd.Stdin = strings.NewReader(string(raw))
		if output, err := cmd.CombinedOutput(); err != nil {
			t.Fatal("real Xray rejected config", err, string(output))
		}
	}
}
func TestXrayAdvancedConversionRejectsWholeIncompatibleGroup(t *testing.T) {
	source := rocketFixture()
	for _, format := range []string{"v2rayn-ha", "v2rayng-ha"} {
		out, err := Convert(source, format, time.Now())
		if err != nil || out.Count != 1 || !json.Valid(out.Body) {
			t.Fatal(format, out, err)
		}
	}
	source.Document["proxies"].([]any)[1].(Record)["type"] = "snell"
	out, err := Convert(source, "v2rayn-ha", time.Now())
	if err == nil || len(out.Body) > 0 || len(out.Skipped) != 1 {
		t.Fatal("partial incompatible group exported", out, err)
	}
}
