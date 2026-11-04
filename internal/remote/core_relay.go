package remote

import (
	"errors"
	"maps"
	"strings"
)

func coreRelayProof(row Record) Record {
	proof, _ := row["goRelay"].(Record)
	return proof
}

// A relay rule must precede generic routing, so a relay never falls through
// to the server's default outbound when we grant a subscription user.
func verifyCoreRelay(doc, row Record) error {
	proof := coreRelayProof(row)
	if proof == nil && row["goRelay"] == nil {
		return nil
	}
	tag, inTag := value(proof["outboundTag"]), value(row["tag"])
	kind := value(proof["kind"])
	section, input, output := relayRoutingFields(kind)
	actionKey, action := "type", "field"
	if kind == "sing-box" {
		actionKey, action = "action", "route"
	}
	outs := anyRecords(doc["outbounds"])
	if !strings.HasPrefix(tag, "mxioc-relay-") || len(outs) < 2 || strings.HasPrefix(value(outs[0]["tag"]), "mxioc-relay-") {
		return errors.New("中转出站或默认出站配置已变化")
	}
	current, err := relayOwnershipFor(doc, tag, inTag, kind)
	if err != nil || current["outboundHash"] != proof["outboundHash"] || current["routeHash"] != proof["routeHash"] {
		return errors.New("中转出站或路由身份已变化")
	}
	routing, err := inboundObject(doc[section])
	if err != nil {
		return err
	}
	if strings.HasPrefix(value(routing["final"]), "mxioc-relay-") {
		return errors.New("中转出站不能作为内核默认出站")
	}
	for _, item := range anyRecords(routing["rules"]) {
		tags := anyStrings(item[input])
		rawTags, _ := item[input].([]any)
		out := value(item[output])
		if len(item) != 3 || item[actionKey] != action || len(rawTags) != 1 || len(tags) != 1 ||
			!strings.HasPrefix(tags[0], "mxioc-inbound-") || !strings.HasPrefix(out, "mxioc-relay-") {
			break
		}
		if out == tag && tags[0] == inTag {
			return nil
		}
		if tags[0] == inTag {
			break
		}
	}
	return errors.New("中转路由优先级已变化")
}

func patchCoreRelay(kind string, doc, row, outbound Record) (Record, error) {
	if len(anyRecords(doc["outbounds"])) == 0 {
		return nil, errors.New("独立内核必须先配置默认出站，才能添加中转")
	}
	tag := value(outbound["tag"])
	if containsConfigString(doc, tag) || containsConfigString(doc, value(row["tag"])) {
		return nil, errors.New("中转标签已被远端配置占用")
	}
	patch := relayPatch
	if kind == "sing-box" {
		patch = patchSingRelay
	}
	next, err := patch(doc, row, outbound)
	if err != nil {
		return nil, err
	}
	proof, err := relayOwnershipFor(next, tag, value(row["tag"]), kind)
	if err != nil {
		return nil, err
	}
	proof["outboundTag"], proof["kind"] = tag, kind
	row["goRelay"] = proof
	if err := verifyCoreRelay(next, row); err != nil {
		return nil, err
	}
	if _, _, err := stripOwnedRelay(next, proof); err != nil {
		return nil, err
	}
	return next, nil
}

func patchSingRelay(doc, row, outbound Record) (Record, error) {
	route, err := coreConfigObject(doc, "route")
	if err != nil {
		return nil, err
	}
	var rules []any
	if route["rules"] != nil {
		var ok bool
		rules, ok = route["rules"].([]any)
		if !ok || len(anyRecords(rules)) != len(rules) {
			return nil, errors.New("sing-box 路由规则格式无效")
		}
	}
	outs, ok := doc["outbounds"].([]any)
	if !ok || len(anyRecords(outs)) != len(outs) {
		return nil, errors.New("sing-box 出站格式无效")
	}
	next := maps.Clone(doc)
	next["outbounds"] = append(append([]any{}, outs...), outbound)
	route["rules"] = append([]any{Record{"inbound": []any{row["tag"]}, "action": "route", "outbound": outbound["tag"]}}, rules...)
	next["route"] = route
	return next, nil
}
