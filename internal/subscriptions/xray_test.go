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
	binary := os.Getenv("MXIOC_TEST_XRAY")
	if binary != "" {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "run", "-test", "-config", "stdin:")
		cmd.Stdin = strings.NewReader(string(got))
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
