package web

import (
	"encoding/json"
	"fmt"
	"testing"
)

func TestPlanAndTrafficHTTPContracts(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	call := func(method, path, body string) map[string]any {
		w := request(s, method, "/admin/api/"+path, body, token, "https://panel.test", true)
		if w.Code != 200 {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		var result map[string]any
		if json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatal("invalid JSON")
		}
		return result
	}
	info := call("GET", "traffic", "")
	if len(info["plans"].([]any)) != 3 {
		t.Fatal("default templates missing")
	}
	info = call("PUT", "traffic", `{"upload":123,"download":456,"total":999999999,"enforce":false,"multiplier":0.5}`)["traffic"].(map[string]any)
	if info["used"] != float64(579) {
		t.Fatal("manual usage lost", info)
	}
	body := `{"name":"自定义","price":99,"monthlyGiB":0.125,"durationMonths":12,"resetPeriod":"monthly","speedMbps":0,"multiplier":1.5}`
	result := call("PUT", "traffic/plans", body)
	plan := result["plan"].(map[string]any)
	id := plan["id"].(string)
	info = call("PUT", "traffic/plan", fmt.Sprintf(`{"planId":%q}`, id))["traffic"].(map[string]any)
	if info["used"] != float64(579) || info["total"] != float64(134217728) || info["planName"] != "自定义" {
		t.Fatal("applied template contract", info)
	}
	snapshot := call("GET", "snapshot", "")
	profileInfo := snapshot["profile"].(map[string]any)["traffic"].(map[string]any)
	if len(profileInfo["plans"].([]any)) != 4 || profileInfo["planId"] != id {
		t.Fatal("snapshot did not include template metadata", profileInfo)
	}
	for _, auth := range []bool{false, true} {
		bearer, origin := "", "https://panel.test"
		status := 401
		if auth {
			bearer = token
			origin = "https://other.test"
			status = 403
		}
		w := request(s, "PUT", "/admin/api/traffic/plans", body, bearer, origin, true)
		if w.Code != status {
			t.Fatal("template mutation bypassed auth/origin", w.Code)
		}
	}
	w := request(s, "PUT", "/admin/api/traffic", `{"total":0}`, token, "https://panel.test", true)
	if w.Code != 400 {
		t.Fatal("zero quota accepted")
	}
	info = call("PUT", "traffic/plans/delete", fmt.Sprintf(`{"id":%q}`, id))["traffic"].(map[string]any)
	if len(info["plans"].([]any)) != 3 || info["total"] != float64(134217728) {
		t.Fatal("deleting template changed existing subscription allowance")
	}
}
