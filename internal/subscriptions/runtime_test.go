package subscriptions

import (
	"context"
	"testing"
)

func TestXPanelCreationRetainsIntentUntilRuntimeCheckAndWarnsForOlderKernels(t *testing.T) {
	c, b, _ := controllerFixture(t)
	b.kind = "x-panel"
	b.rows[0]["protocol"] = "vless"
	b.rows[0]["settings"] = Record{"clients": []any{}}
	b.rows[0]["streamSettings"] = Record{"network": "tcp", "security": "none"}
	b.runtimeFailure = true
	result, err := c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil || result["failed"] != 1 || b.adds != 1 {
		t.Fatal(result, err)
	}
	if stateBinding(t, c)["status"] != "provisioning" {
		t.Fatal("unconfirmed runtime lost pending ownership")
	}
	b.runtimeFailure = false
	b.runtimeResult = Record{"runtimeVerified": true, "runtimeRepaired": true}
	result, err = c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil || result["succeeded"] != 1 || b.adds != 1 {
		t.Fatal("runtime retry created another user", result, err)
	}
	item := result["results"].([]any)[0].(Record)
	if item["runtimeVerified"] != true || item["warning"] != "已补同步到运行内核" {
		t.Fatal("runtime result not propagated", item)
	}
	b.runtimeResult = nil
	result, err = c.Batch(context.Background(), "clash", "s", []int{1})
	if err != nil || result["existing"] != 1 || b.ops[len(b.ops)-1] != "verify" {
		t.Fatal("repeat import skipped explicit runtime verification", result, err)
	}
	item = result["results"].([]any)[0].(Record)
	if item["runtimeVerified"] != nil || item["warning"] != "当前内核不支持运行用户核验，请测试客户端连接" {
		t.Fatal("unsupported kernel claimed verified", item)
	}
	before := len(b.ops)
	if _, err = c.Sync(context.Background(), "clash"); err != nil {
		t.Fatal(err)
	}
	if len(b.ops) != before+1 || b.ops[len(b.ops)-1] != "read" {
		t.Fatal("background metering performed user runtime repair")
	}
}
