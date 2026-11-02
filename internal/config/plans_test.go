package config

import (
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func planPayload() Document {
	return Document{"name": "自定义套餐", "price": json.Number("12.50"), "monthlyGiB": json.Number("0.125"), "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": json.Number("0.5")}
}
func TestPlanCRUDDefaultsAndUnknownFieldPreservation(t *testing.T) {
	r, _, _ := fixture(t)
	plans, err := r.Plans()
	if err != nil || len(plans) != 3 || plans[0]["price"] != 120 || plans[2]["price"] != nil {
		t.Fatal(plans, err)
	}
	created, err := r.SavePlan(planPayload())
	if err != nil {
		t.Fatal(err)
	}
	id := created["id"].(string)
	index, _ := r.index()
	index["future"] = json.Number("9007199254740993")
	for _, v := range index["subscriptionPlans"].([]any) {
		p := v.(map[string]any)
		if p["id"] == id {
			p["unknown"] = "preserve"
		}
	}
	if err = r.writeIndex(index); err != nil {
		t.Fatal(err)
	}
	edit := planPayload()
	edit["id"] = id
	edit["name"] = "修改套餐"
	if _, err = r.SavePlan(edit); err != nil {
		t.Fatal(err)
	}
	index, _ = r.index()
	if index["future"] != json.Number("9007199254740993") {
		t.Fatal("unknown index field lost")
	}
	plans, _ = r.Plans()
	if plans[3]["unknown"] != "preserve" {
		t.Fatal("unknown plan field lost")
	}
	p, err := r.Plan(id)
	if err != nil || p["name"] != "修改套餐" {
		t.Fatal(p, err)
	}
	for _, plan := range plans {
		if err = r.DeletePlan(plan["id"].(string)); err != nil {
			t.Fatal(err)
		}
	}
	plans, err = r.Plans()
	if err != nil || len(plans) != 0 {
		t.Fatal("deleted defaults resurrected")
	}
	profiles, err := r.Profiles()
	if err != nil || len(profiles[0]["traffic"].(Document)["plans"].([]Document)) != 0 {
		t.Fatal("profile template list stale", profiles, err)
	}
}
func TestPlanValidationAndExactGiBConversion(t *testing.T) {
	if n, e := PlanBytes(json.Number("0.125")); e != nil || n != 134217728 {
		t.Fatal(n, e)
	}
	if n, e := PlanUnits(json.Number("0.123")); e != nil || n != 123 {
		t.Fatal(n, e)
	}
	r, _, _ := fixture(t)
	before, _ := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
	for _, change := range []Document{{"monthlyGiB": json.Number("1e1000000000")}, {"monthlyGiB": json.Number("0")}, {"monthlyGiB": math.NaN()}, {"price": true}, {"durationMonths": json.Number("12.5")}, {"multiplier": json.Number("1.0001")}, {"speedMbps": json.Number("0.001")}, {"name": strings.Repeat("中", 61)}, {"resetPeriod": "weekly"}, {"id": "deleted"}} {
		p := planPayload()
		for k, v := range change {
			p[k] = v
		}
		if _, err := r.SavePlan(p); err == nil {
			t.Fatal("invalid plan accepted", change)
		}
	}
	after, _ := os.ReadFile(filepath.Join(r.Root, "profiles.json"))
	if string(before) != string(after) {
		t.Fatal("rejected template changed storage")
	}
}
