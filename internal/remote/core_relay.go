package remote

import (
	"errors"
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
	outs := anyRecords(doc["outbounds"])
	if !strings.HasPrefix(tag, "mxioc-relay-") || len(outs) < 2 || strings.HasPrefix(value(outs[0]["tag"]), "mxioc-relay-") {
		return errors.New("中转出站或默认出站配置已变化")
	}
	current, err := relayOwnership(doc, tag, inTag)
	if err != nil || current["outboundHash"] != proof["outboundHash"] || current["routeHash"] != proof["routeHash"] {
		return errors.New("中转出站或路由身份已变化")
	}
	routing, err := inboundObject(doc["routing"])
	if err != nil {
		return err
	}
	for _, item := range anyRecords(routing["rules"]) {
		tags := anyStrings(item["inboundTag"])
		rawTags, _ := item["inboundTag"].([]any)
		out := value(item["outboundTag"])
		if len(item) != 3 || item["type"] != "field" || len(rawTags) != 1 || len(tags) != 1 ||
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

func patchCoreRelay(doc, row, outbound Record) (Record, error) {
	if len(anyRecords(doc["outbounds"])) == 0 {
		return nil, errors.New("独立 Xray 必须先配置默认出站，才能添加中转")
	}
	tag := value(outbound["tag"])
	if containsConfigString(doc, tag) || containsConfigString(doc, value(row["tag"])) {
		return nil, errors.New("中转标签已被远端配置占用")
	}
	next, err := relayPatch(doc, row, outbound)
	if err != nil {
		return nil, err
	}
	proof, err := relayOwnership(next, tag, value(row["tag"]))
	if err != nil {
		return nil, err
	}
	proof["outboundTag"] = tag
	row["goRelay"] = proof
	if err := verifyCoreRelay(next, row); err != nil {
		return nil, err
	}
	if _, _, err := stripOwnedRelay(next, proof); err != nil {
		return nil, err
	}
	return next, nil
}
