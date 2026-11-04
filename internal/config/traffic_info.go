package config

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"time"

	"github.com/Angasky/dingzhi-ban/internal/billing"
)

func trafficNumber(value any, fallback int64) (int64, error) {
	if value == nil {
		return fallback, nil
	}
	var text string
	switch v := value.(type) {
	case int:
		text = strconv.Itoa(v)
	case int64:
		text = strconv.FormatInt(v, 10)
	case json.Number:
		text = string(v)
	default:
		return 0, errors.New("流量字段必须为整数")
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil || n < 0 {
		return 0, errors.New("流量字段超出范围")
	}
	return n, nil
}

// TrafficInfo is shared by profile/snapshot and the dedicated traffic endpoint.
// Its whitelist never exposes encrypted recovery credentials or local paths.
func TrafficInfo(record Document, now time.Time) (Document, error) {
	t, _ := record["traffic"].(map[string]any)
	if t == nil {
		t = Document{}
	}
	upload, err := trafficNumber(t["upload"], 0)
	if err != nil {
		return nil, err
	}
	download, err := trafficNumber(t["download"], 0)
	if err != nil {
		return nil, err
	}
	used, err := billing.Add(upload, download)
	if err != nil {
		return nil, err
	}
	rawUp, err := trafficNumber(t["rawUpload"], 0)
	if err != nil {
		return nil, err
	}
	rawDown, err := trafficNumber(t["rawDownload"], 0)
	if err != nil {
		return nil, err
	}
	rawUsed, err := billing.Add(rawUp, rawDown)
	if err != nil {
		return nil, err
	}
	units, err := trafficNumber(t["multiplierUnits"], 1000)
	if err != nil || units > 100000 {
		return nil, errors.New("流量倍率无效")
	}
	bindings := []any{}
	for index, v := range rows(record, "remoteNodes") {
		b, ok := v.(map[string]any)
		if !ok {
			return nil, errors.New("用户绑定格式无效")
		}
		out := Document{"recordIndex": index, "recordToken": BindingToken(stringValue(record["id"]), b)}
		for _, k := range []string{"scope", "serverId", "inboundId", "name", "port", "status", "error", "importedNames", "multiplierUnits", "up", "down", "lastSampleAt", "lastRawDelta", "monthlyPaused", "counterSource", "legacyMeterRetained"} {
			if value, exists := b[k]; exists {
				out[k] = value
			}
		}
		bindings = append(bindings, out)
	}
	var total, expire, remaining any
	exhausted, expired := false, false
	percent := float64(0)
	if t["total"] != nil {
		n, e := trafficNumber(t["total"], 0)
		if e != nil {
			return nil, e
		}
		total = n
		left := n - used
		if left < 0 {
			left = 0
		}
		remaining = left
		exhausted = used >= n
		if n > 0 {
			percent = math.Min(100, math.Round(float64(used)/float64(n)*10000)/100)
		}
	}
	if t["expire"] != nil {
		n, e := trafficNumber(t["expire"], 0)
		if e != nil {
			return nil, e
		}
		expire = n
		expired = n <= now.Unix()
	}
	info := Document{"configured": t["enabled"] == true, "enforce": t["enforce"] == true, "upload": upload, "download": download, "used": used, "total": total, "expire": expire, "remaining": remaining, "percent": percent, "exhausted": exhausted, "expired": expired, "rawUpload": rawUp, "rawDownload": rawDown, "rawUsed": rawUsed, "multiplier": float64(units) / 1000, "resetPeriod": t["resetPeriod"], "nextResetAt": t["nextResetAt"], "updatedAt": t["updatedAt"], "bindings": bindings, "enforcementError": record["enforcementError"], "lastCheckedAt": record["lastEnforcedAt"], "revoked": record["accessRevoked"] == true}
	for _, key := range []string{"planId", "planName", "price", "durationMonths", "speedMbps", "cycleAnchor"} {
		info[key] = t[key]
	}
	return info, nil
}
