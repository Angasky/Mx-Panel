package config

import "reflect"

var legacyDefaultDNS = []any{"https://1.1.1.1/dns-query#%E2%9C%88%EF%B8%8F%20Proxy", "https://dns.google/dns-query#%E2%9C%88%EF%B8%8F%20Proxy"}
var domesticDefaultDNS = []any{"https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"}
var legacySTUNRules = []string{"DOMAIN-KEYWORD,stun,REJECT", "AND,((NETWORK,UDP),(DST-PORT,3478-3481)),REJECT", "AND,((NETWORK,UDP),(DST-PORT,5349)),REJECT", "AND,((NETWORK,UDP),(DST-PORT,19302-19309)),REJECT"}

// Recognize the shipped MXIOC defaults rather than rewriting arbitrary user DNS.
// Individual custom fields and non-default rules remain untouched.
func repairDefaultConnectivity(doc Document) bool {
	dns, ok := doc["dns"].(Document)
	if !ok {
		return false
	}
	known := map[string]bool{}
	for _, v := range rows(doc, "proxy-groups") {
		if g, ok := v.(Document); ok {
			known[stringValue(g["name"])] = true
		}
	}
	if !known["✈️ Proxy"] || !known["🛡️ 基础广告拦截"] || !known["🌏 爱奇艺&哔哩哔哩"] || !reflect.DeepEqual(dns["nameserver"], legacyDefaultDNS) {
		return false
	}
	changed := false
	if dns["enhanced-mode"] == "fake-ip" && dns["fake-ip-filter-mode"] == "rule" && reflect.DeepEqual(dns["fake-ip-filter"], []any{"GEOSITE,private,real-ip", "MATCH,fake-ip"}) {
		dns["fake-ip-filter"] = []any{"GEOSITE,private,real-ip", "GEOSITE,cn,real-ip", "MATCH,fake-ip"}
		changed = true
	}
	dns["nameserver"] = append([]any(nil), domesticDefaultDNS...)
	changed = true
	// Explicit foreign policies retain their selected proxy DNS. Domestic lookups
	// use reachable resolvers even when the selected proxy is unavailable.
	policy, ok := dns["nameserver-policy"].(Document)
	if !ok && dns["nameserver-policy"] == nil {
		policy = Document{}
		dns["nameserver-policy"] = policy
	}
	if policy != nil && policy["geosite:cn"] == nil {
		policy["geosite:cn"] = append([]any(nil), domesticDefaultDNS...)
	}
	present := map[string]bool{}
	for _, r := range rows(doc, "rules") {
		present[stringValue(r)] = true
	}
	all := true
	for _, r := range legacySTUNRules {
		all = all && present[r]
	}
	if all {
		blocked := map[string]bool{}
		for _, r := range legacySTUNRules {
			blocked[r] = true
		}
		rules := []any{}
		for _, r := range rows(doc, "rules") {
			if !blocked[stringValue(r)] {
				rules = append(rules, r)
			}
		}
		doc["rules"] = rules
	}
	for _, v := range rows(doc, "proxy-groups") {
		g, ok := v.(Document)
		if ok && g["name"] == "🛡️ 基础广告拦截" && reflect.DeepEqual(g["proxies"], []any{"REJECT", "DIRECT"}) {
			g["proxies"] = []any{"DIRECT", "REJECT"}
		}
	}
	return changed
}

// Mutate supplies durable pre-change backups and updates all profile mirrors.
func (r *Repository) RepairLegacyDefaultConnectivity() (int, error) {
	profiles, e := r.Profiles()
	if e != nil {
		return 0, e
	}
	count := 0
	for _, p := range profiles {
		changed := false
		e = r.Mutate(stringValue(p["id"]), func(doc Document) error { changed = repairDefaultConnectivity(doc); return nil })
		if e != nil {
			return count, e
		}
		if changed {
			count++
		}
	}
	return count, nil
}
