package config

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/Angasky/dingzhi-ban/internal/billing"
)

func decimalText(value any) (string, error) {
	switch n := value.(type) {
	case json.Number:
		return string(n), nil
	case int:
		return strconv.Itoa(n), nil
	case int64:
		return strconv.FormatInt(n, 10), nil
	case float64:
		if !math.IsInf(n, 0) && !math.IsNaN(n) {
			return strconv.FormatFloat(n, 'g', -1, 64), nil
		}
	}
	return "", errors.New("模板数值无效")
}
func planDecimal(value any, minimum, maximum float64) (*big.Rat, error) {
	text, err := decimalText(value)
	if err != nil || len(text) > 64 {
		return nil, errors.New("模板数值无效")
	}
	if _, exp, ok := strings.Cut(strings.ToLower(text), "e"); ok {
		n, e := strconv.Atoi(exp)
		if e != nil || n < -18 || n > 18 {
			return nil, errors.New("模板数值精度超出范围")
		}
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil || math.IsInf(f, 0) || math.IsNaN(f) || f < minimum || f > maximum {
		return nil, errors.New("模板数值超出范围")
	}
	n, ok := new(big.Rat).SetString(text)
	if !ok {
		return nil, errors.New("模板数值无效")
	}
	lower, _ := new(big.Rat).SetString(strconv.FormatFloat(minimum, 'g', -1, 64))
	upper, _ := new(big.Rat).SetString(strconv.FormatFloat(maximum, 'g', -1, 64))
	if n.Cmp(lower) < 0 || n.Cmp(upper) > 0 {
		return nil, errors.New("模板数值超出范围")
	}
	return n, nil
}

// PlanBytes converts decimal GiB exactly and rounds ties to even, avoiding
// float drift when a custom template uses a fractional monthly allowance.
func PlanBytes(value any) (int64, error) {
	n, err := planDecimal(value, 0.001, 1000000)
	if err != nil {
		return 0, err
	}
	n.Mul(n, big.NewRat(1024*1024*1024, 1))
	q, remainder := new(big.Int), new(big.Int)
	q.QuoRem(n.Num(), n.Denom(), remainder)
	comparison := new(big.Int).Lsh(remainder, 1).Cmp(n.Denom())
	if comparison > 0 || comparison == 0 && q.Bit(0) == 1 {
		q.Add(q, big.NewInt(1))
	}
	if !q.IsInt64() {
		return 0, errors.New("流量额度超出范围")
	}
	return q.Int64(), nil
}
func PlanUnits(value any) (int64, error) {
	return billing.ScaledDecimal(value, 1000, 100)
}
func normalizedPlan(payload Document) (Document, error) {
	name := strings.TrimSpace(stringValue(payload["name"]))
	if name == "" || utf8.RuneCountInString(name) > 60 || strings.ContainsAny(name, "\r\n\x00") {
		return nil, errors.New("模板名称须为 1–60 个字符")
	}
	if _, err := PlanBytes(payload["monthlyGiB"]); err != nil {
		return nil, err
	}
	price := payload["price"]
	if price == "" {
		price = nil
	}
	if price != nil {
		if _, err := planDecimal(price, 0, 100000000); err != nil {
			return nil, err
		}
	}
	months, err := trafficNumber(payload["durationMonths"], 12)
	if err != nil || months < 1 || months > 120 {
		return nil, errors.New("有效期必须为 1–120 个整月")
	}
	period := stringValue(payload["resetPeriod"])
	if period == "" {
		period = "monthly"
	}
	if period != "monthly" && period != "none" {
		return nil, errors.New("流量重置周期无效")
	}
	kbps, err := billing.BandwidthKbps(payload["speedMbps"])
	if err != nil {
		return nil, err
	}
	speed := json.Number(strconv.FormatFloat(float64(kbps)/1000, 'f', -1, 64))
	multiplier := payload["multiplier"]
	if multiplier == nil {
		multiplier = 1
	}
	units, err := PlanUnits(multiplier)
	if err != nil {
		return nil, err
	}
	return Document{"id": payload["id"], "name": name, "price": price, "monthlyGiB": payload["monthlyGiB"], "durationMonths": months, "resetPeriod": period, "speedMbps": speed, "multiplier": json.Number(strconv.FormatFloat(float64(units)/1000, 'f', -1, 64))}, nil
}
func plansFrom(index Document) ([]Document, error) {
	if raw, present := index["subscriptionPlans"]; present {
		list, ok := raw.([]any)
		if !ok {
			return nil, errors.New("套餐模板列表格式无效")
		}
		out := []Document{}
		seen := map[string]bool{}
		for _, v := range list {
			row, ok := v.(map[string]any)
			if !ok {
				return nil, errors.New("套餐模板格式无效")
			}
			copy := Document{"durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 1}
			for k, v := range row {
				copy[k] = v
			}
			id := stringValue(copy["id"])
			if id == "" || seen[id] {
				return nil, errors.New("套餐模板 ID 无效或重复")
			}
			seen[id] = true
			out = append(out, copy)
		}
		return out, nil
	}
	return []Document{{"id": "tier-1", "name": "档位1", "price": 120, "monthlyGiB": 50, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 1}, {"id": "tier-2", "name": "档位2", "price": 240, "monthlyGiB": 100, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 1}, {"id": "tier-3", "name": "档位3", "price": nil, "monthlyGiB": 150, "durationMonths": 12, "resetPeriod": "monthly", "speedMbps": 0, "multiplier": 1}}, nil
}
func (r *Repository) Plans() ([]Document, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	return plansFrom(index)
}
func (r *Repository) SavePlan(payload Document) (Document, error) {
	validated, err := normalizedPlan(payload)
	if err != nil {
		return nil, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return nil, err
	}
	plans, err := plansFrom(index)
	if err != nil {
		return nil, err
	}
	id := stringValue(payload["id"])
	found := false
	for _, old := range plans {
		if old["id"] == id {
			for k, v := range validated {
				old[k] = v
			}
			validated = old
			found = true
			break
		}
	}
	if id != "" && !found {
		return nil, errors.New("模板已不存在，请刷新")
	}
	if id == "" {
		if len(plans) >= 100 {
			return nil, errors.New("最多保存 100 个套餐模板")
		}
		token, err := randomToken(8)
		if err != nil {
			return nil, err
		}
		validated["id"] = "plan-" + token
		plans = append(plans, validated)
	}
	index["subscriptionPlans"] = plans
	if err = r.writeIndex(index); err != nil {
		return nil, err
	}
	return validated, nil
}
func (r *Repository) DeletePlan(id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, err := r.index()
	if err != nil {
		return err
	}
	plans, err := plansFrom(index)
	if err != nil {
		return err
	}
	next := []Document{}
	found := false
	for _, plan := range plans {
		if plan["id"] == id {
			found = true
		} else {
			next = append(next, plan)
		}
	}
	if !found {
		return errors.New("模板已不存在")
	}
	index["subscriptionPlans"] = next
	return r.writeIndex(index)
}
func (r *Repository) Plan(id string) (Document, error) {
	plans, err := r.Plans()
	if err != nil {
		return nil, err
	}
	for _, p := range plans {
		if p["id"] == id {
			return normalizedPlan(p)
		}
	}
	return nil, errors.New("请选择有效套餐模板")
}
