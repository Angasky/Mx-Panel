package config

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
)

// These are explicit per-subscription export overrides; the source YAML is kept
// intact so deleting overrides restores custom configuration without guessing.
type ClientOptions struct {
	DNSMode        string `json:"dnsMode"`
	WebRTCMode     string `json:"webRTCMode"`
	WebRTC         bool   `json:"webRTC"`
	DNSProtection  bool   `json:"dnsProtection"`
	DomesticRealIP bool   `json:"domesticRealIP"`
	IPv6           bool   `json:"ipv6"`
	BasicAds       bool   `json:"basicAds"`
	StrongAds      bool   `json:"strongAds"`
	XrayExport     bool   `json:"xrayExport"`
	SingBoxExport  bool   `json:"singBoxExport"`
}

func readClientOptions(record Document) (*ClientOptions, error) {
	value, exists := record["clientOptions"]
	if !exists || value == nil {
		return nil, nil
	}
	raw, e := json.Marshal(value)
	if e != nil {
		return nil, e
	}
	var o ClientOptions
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&o); e != nil {
		return nil, errors.New("客户端设置损坏")
	}
	return &o, nil
}
func inferredClientOptions(doc Document) ClientOptions {
	o := ClientOptions{SingBoxExport: true, IPv6: doc["ipv6"] == true}
	dns, _ := doc["dns"].(Document)
	for _, v := range rows(dns, "fake-ip-filter") {
		if strings.EqualFold(stringValue(v), "GEOSITE,cn,real-ip") {
			o.DomesticRealIP = true
		}
	}
	for _, v := range rows(doc, "rules") {
		if v == legacySTUNRules[0] {
			o.WebRTC = true
		}
	}
	for _, v := range rows(doc, "proxy-groups") {
		g, ok := v.(Document)
		if !ok {
			continue
		}
		members := rows(g, "proxies")
		if len(members) == 0 {
			continue
		}
		if g["name"] == "🛡️ 基础广告拦截" {
			o.BasicAds = members[0] == "REJECT"
		}
		if g["name"] == "🔥 强力广告拦截" {
			o.StrongAds = members[0] == "REJECT"
		}
	}
	return o
}
func (r *Repository) ClientOptions(id string) (ClientOptions, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, e := r.index()
	if e != nil {
		return ClientOptions{}, false, e
	}
	state, e := stateRecord(index, id)
	if e != nil {
		return ClientOptions{}, false, e
	}
	o, e := readClientOptions(state)
	if e != nil {
		return ClientOptions{}, false, e
	}
	if o != nil {
		return *o, true, nil
	}
	p, e := r.profile(id)
	if e != nil {
		return ClientOptions{}, false, e
	}
	doc, _, e := r.cachedRead(p)
	return inferredClientOptions(doc), false, e
}
func (r *Repository) SetClientOptions(id string, options *ClientOptions) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	index, e := r.index()
	if e != nil {
		return e
	}
	state, e := stateRecord(index, id)
	if e != nil {
		return e
	}
	if options == nil {
		delete(state, "clientOptions")
	} else {
		p, e := r.profile(id)
		if e != nil {
			return e
		}
		doc, _, e := r.cachedRead(p)
		if e != nil {
			return e
		}
		if _, e = applyClientOptions(doc, *options); e != nil {
			return e
		}
		raw, _ := json.Marshal(options)
		var value Document
		json.Unmarshal(raw, &value)
		state["clientOptions"] = value
	}
	return r.writeIndex(index)
}
func applyClientOptions(original Document, o ClientOptions) (Document, error) {
	if o.DNSMode != "" && o.DNSMode != "strict" && o.DNSMode != "domestic" {
		return nil, errors.New("DNS 模式无效")
	}
	if o.WebRTCMode != "" && o.WebRTCMode != "block" && o.WebRTCMode != "chrome-proxy" {
		return nil, errors.New("WebRTC 模式无效")
	}
	doc := cloneConfig(original).(Document)
	if o.WebRTC && o.WebRTCMode == "chrome-proxy" {
		found := false
		for _, v := range rows(doc, "proxy-groups") {
			g, _ := v.(Document)
			if g["name"] == "✈️ Proxy" {
				found = true
			}
		}
		if !found {
			return nil, errors.New("Chrome UDP 模式需要「✈️ Proxy」策略组")
		}
	}

	// Remove only the known block rules. Other user rules remain in order.
	block := map[string]bool{}
	for _, rule := range legacySTUNRules {
		block[rule] = true
	}
	rules := []any{}
	if o.WebRTC {
		if o.WebRTCMode == "chrome-proxy" {
			rules = append(rules, "AND,((PROCESS-NAME,com.android.chrome),(NETWORK,UDP)),✈️ Proxy")
			doc["find-process-mode"] = "always"
		} else {
			for _, rule := range legacySTUNRules {
				rules = append(rules, rule)
			}
		}
	}
	for _, rule := range rows(doc, "rules") {
		if !block[stringValue(rule)] {
			rules = append(rules, rule)
		}
	}
	doc["rules"] = rules
	dns, ok := doc["dns"].(Document)
	if !ok {
		dns = Document{}
		doc["dns"] = dns
	}
	doc["ipv6"] = o.IPv6
	dns["ipv6"] = o.IPv6
	// Use rule-mode when opting into the domain real-IP exception. Convert legacy
	// blacklist entries to equivalent domain conditions, leaving the source intact.
	filter := []any{}
	ruleMode := dns["fake-ip-filter-mode"] == "rule"
	if !ruleMode && dns["fake-ip-filter-mode"] != nil && dns["fake-ip-filter-mode"] != "blacklist" && o.DomesticRealIP {
		return nil, errors.New("当前 fake-IP 使用 whitelist 模式，请先在 DNS 页面切换为 blacklist 或 rule")
	}
	for _, v := range rows(dns, "fake-ip-filter") {
		rule := stringValue(v)
		if ruleMode {
			if strings.EqualFold(rule, "GEOSITE,cn,real-ip") {
				continue
			}
			filter = append(filter, v)
		} else if o.DomesticRealIP {
			if strings.HasPrefix(rule, "+.") {
				filter = append(filter, "DOMAIN-SUFFIX,"+strings.TrimPrefix(rule, "+.")+",real-ip")
			} else if strings.HasPrefix(rule, "geosite:") {
				filter = append(filter, "GEOSITE,"+strings.TrimPrefix(rule, "geosite:")+",real-ip")
			} else {
				filter = append(filter, "DOMAIN-WILDCARD,"+rule+",real-ip")
			}
		} else {
			filter = append(filter, v)
		}
	}
	if o.DomesticRealIP {
		if !ruleMode {
			dns["fake-ip-filter-mode"] = "rule"
			filter = append(filter, "MATCH,fake-ip")
		}
		filter = append([]any{"GEOSITE,cn,real-ip"}, filter...)
	}
	if ruleMode || o.DomesticRealIP {
		dns["fake-ip-filter"] = filter
	}
	if o.DNSProtection {
		proxy := ""
		for _, v := range rows(doc, "proxy-groups") {
			g, ok := v.(Document)
			if ok && g["name"] == "✈️ Proxy" {
				proxy = "✈️ Proxy"
			}
		}
		if proxy == "" {
			return nil, errors.New("DNS 防泄露需要名为「✈️ Proxy」的策略组，请先配置代理组")
		}
		remote := []any{"https://1.1.1.1/dns-query#" + url.PathEscape(proxy), "https://dns.google/dns-query#" + url.PathEscape(proxy)}
		dns["enable"] = true
		dns["respect-rules"] = true
		dns["nameserver"] = remote
		dns["fallback"] = []any{}
		delete(dns, "fallback-filter")
		// All client DNS queries use proxy DoH. Only resolving proxy server addresses
		// and resolver bootstrap intentionally stays direct to avoid a dependency loop.
		dns["nameserver-policy"] = Document{}
		dns["direct-nameserver"] = remote
		dns["direct-nameserver-follow-policy"] = false
		if o.DNSMode == "domestic" {
			local := []any{"https://dns.alidns.com/dns-query#DIRECT", "https://doh.pub/dns-query#DIRECT"}
			dns["nameserver-policy"] = Document{"geosite:cn": local, "geosite:private": local}
			dns["direct-nameserver-follow-policy"] = true
		}
		dns["proxy-server-nameserver"] = append([]any(nil), domesticDefaultDNS...)
		dns["default-nameserver"] = []any{"223.5.5.5", "119.29.29.29"}
		tun, ok := doc["tun"].(Document)
		if !ok {
			tun = Document{}
			doc["tun"] = tun
		}
		tun["dns-hijack"] = []any{"any:53", "tcp://any:53"}
	}
	for _, v := range rows(doc, "proxy-groups") {
		g, ok := v.(Document)
		if !ok {
			continue
		}
		enabled := false
		switch g["name"] {
		case "🛡️ 基础广告拦截":
			enabled = o.BasicAds
		case "🔥 强力广告拦截":
			enabled = o.StrongAds
		default:
			continue
		}
		extras := []any{}
		for _, member := range rows(g, "proxies") {
			if member != "DIRECT" && member != "REJECT" {
				extras = append(extras, member)
			}
		}
		if enabled {
			g["proxies"] = append([]any{"REJECT", "DIRECT"}, extras...)
		} else {
			g["proxies"] = append([]any{"DIRECT", "REJECT"}, extras...)
		}
	}
	if e := validate(doc); e != nil {
		return nil, e
	}
	return doc, nil
}
