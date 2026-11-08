package remote

import (
	"errors"
	"strconv"
	"strings"
)

// Python's link importer stores numeric HY2 rates as "N Mbps". sing-box
// requires integral Mbps; reject unsupported units and fractions rather than
// rounding or silently omitting a requested congestion-control setting.
func legacyHysteriaMbps(raw any) (int, error) {
	text := value(raw)
	if n, ok := raw.(float64); ok {
		text = strconv.FormatFloat(n, 'f', -1, 64)
	}
	text = strings.Trim(text, " ")
	text = strings.TrimSuffix(text, "Mbps")
	text = strings.Trim(text, " ")
	if text == "" {
		return 0, errors.New("缺少 Hysteria2 带宽")
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, errors.New("Hysteria2 带宽须为整数 Mbps")
		}
	}
	n, err := strconv.ParseInt(text, 10, 32)
	if err != nil || n <= 0 {
		return 0, errors.New("Hysteria2 带宽超出范围")
	}
	return int(n), nil
}
