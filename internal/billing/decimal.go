package billing

import (
	"encoding/json"
	"errors"
	"math"
	"math/big"
	"regexp"
	"strconv"
	"strings"
)

var decimalSyntax = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)

// ScaledDecimal accepts decimal notation only, never Rat's fractions or hex.
// Length and exponent bounds prevent untrusted inputs from allocating huge integers.
func ScaledDecimal(raw any, scale, maximum int64) (int64, error) {
	var value string
	switch n := raw.(type) {
	case string:
		value = n
	case json.Number:
		value = string(n)
	case int:
		value = strconv.Itoa(n)
	case int64:
		value = strconv.FormatInt(n, 10)
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, errors.New("数值必须为有限小数")
		}
		value = strconv.FormatFloat(n, 'g', -1, 64)
	default:
		return 0, errors.New("数值格式无效")
	}
	if len(value) > 256 {
		return 0, errors.New("数值过长")
	}
	value = strings.ReplaceAll(strings.TrimSpace(value), "_", "")
	if !decimalSyntax.MatchString(value) {
		return 0, errors.New("数值必须为十进制小数")
	}
	if _, exp, ok := strings.Cut(strings.ToLower(value), "e"); ok {
		n, err := strconv.Atoi(exp)
		if err != nil || n < -256 || n > 256 {
			return 0, errors.New("数值指数超出范围")
		}
	}
	ratio, ok := new(big.Rat).SetString(value)
	if !ok || ratio.Sign() < 0 || ratio.Cmp(big.NewRat(maximum, 1)) > 0 {
		return 0, errors.New("数值超出范围")
	}
	ratio.Mul(ratio, big.NewRat(scale, 1))
	if !ratio.IsInt() || !ratio.Num().IsInt64() {
		return 0, errors.New("数值精度超出范围")
	}
	return ratio.Num().Int64(), nil
}

// BandwidthKbps includes the dedicated port policer's minimum nonzero rate.
func BandwidthKbps(raw any) (int, error) {
	if raw == nil || raw == "" {
		return 0, nil
	}
	n, err := ScaledDecimal(raw, 1000, 10000)
	if err != nil {
		return 0, err
	}
	if n > 0 && n < 100 {
		return 0, errors.New("带宽须为 0 或 0.1–10000 Mbps")
	}
	return int(n), nil
}
