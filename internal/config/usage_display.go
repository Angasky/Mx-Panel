package config

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"unicode"
	"unicode/utf8"
)

type UsageDisplay struct {
	Enabled   bool   `json:"enabled"`
	Used      string `json:"used"`
	Remaining string `json:"remaining"`
	Expiry    string `json:"expiry"`
}

var ErrUsageDisplayChanged = errors.New("流量信息节点设置已变更，请刷新后重试")

func (o UsageDisplay) Validate() error {
	for _, f := range []struct {
		value string
		vars  []string
	}{{o.Used, []string{"used", "total"}}, {o.Remaining, []string{"remaining"}}, {o.Expiry, []string{"expiry"}}} {
		if f.value == "" {
			continue
		}
		if !utf8.ValidString(f.value) || utf8.RuneCountInString(f.value) > 128 || strings.ContainsFunc(f.value, func(r rune) bool { return unicode.IsControl(r) || unicode.Is(unicode.Cf, r) }) {
			return errors.New("名称模板最多 128 个字符，不允许换行、控制字符或隐藏格式字符")
		}
		rest := f.value
		for _, v := range f.vars {
			token := "{" + v + "}"
			if strings.Count(rest, token) != 1 {
				return errors.New("已用模板须各含一次 {used}、{total}；剩余须含一次 {remaining}；到期须含一次 {expiry}")
			}
			rest = strings.ReplaceAll(rest, token, "")
		}
		if strings.ContainsAny(rest, "{}") {
			return errors.New("名称模板包含不支持的变量或花括号")
		}
	}
	return nil
}
func (o UsageDisplay) Revision() string {
	b, _ := json.Marshal(o)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func readUsageDisplay(record Document) (UsageDisplay, error) {
	o := UsageDisplay{Enabled: true}
	if value, ok := record["usageDisplay"]; ok {
		b, e := json.Marshal(value)
		if e != nil || string(b) == "null" {
			return o, errors.New("流量信息节点设置损坏")
		}
		if e = json.Unmarshal(b, &o); e != nil {
			return o, e
		}
	}
	return o, o.Validate()
}
func (r *Repository) UsageDisplay(id string) (UsageDisplay, error) {
	state, e := r.State(id)
	if e != nil {
		return UsageDisplay{}, e
	}
	return readUsageDisplay(state)
}
func (r *Repository) SetUsageDisplay(id string, o UsageDisplay, revision string) error {
	if e := o.Validate(); e != nil {
		return e
	}
	return r.UpdateState(id, func(record Document) error {
		previous, e := readUsageDisplay(record)
		if e != nil {
			return e
		}
		if previous.Revision() != revision {
			return ErrUsageDisplayChanged
		}
		b, _ := json.Marshal(o)
		var value Document
		if e := json.Unmarshal(b, &value); e != nil {
			return e
		}
		record["usageDisplay"] = value
		return nil
	})
}
