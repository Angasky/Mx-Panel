package web

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGoPolicyTemplateAndGroupRoutingWorkflow(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	const origin = "https://panel.test"
	const templates = "/admin/api/policy-templates"
	if w := request(s, "GET", templates, "", "", "", true); w.Code != 401 {
		t.Fatal("template listing must be authenticated")
	}
	if w := request(s, "GET", templates+"?source=default", "", token, origin, true); w.Code != 200 ||
		!strings.Contains(w.Body.String(), "RULE-SET") {
		t.Fatal("embedded default template missing", w.Code)
	}
	const group = `{"config":{"name":"Binance","type":"select","proxies":["DIRECT"]},"groupRules":["binance.com","IP-CIDR,192.0.2.0/24,no-resolve"],"expectedGroupRules":[]}`
	if w := request(s, "POST", "/admin/api/groups", group, token, origin, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := request(s, "PUT", "/admin/api/groups", `{"oldName":"Binance","config":{"name":"Binance","type":"select","proxies":["DIRECT"]},"groupRules":[],"expectedGroupRules":[]}`, token, origin, true); w.Code != 400 {
		t.Fatal("stale group rules should be rejected", w.Code)
	}
	w := request(s, "GET", templates+"?source=current", "", token, origin, true)
	var seeded struct {
		Template map[string]any
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &seeded) != nil || seeded.Template == nil {
		t.Fatal(w.Code, w.Body.String())
	}
	seeded.Template["name"] = "Exchange"
	payload, err := json.Marshal(seeded.Template)
	if err != nil {
		t.Fatal(err)
	}
	if w := request(s, "POST", templates, string(payload), token, "https://foreign.test", true); w.Code != 403 {
		t.Fatal("foreign origin write accepted", w.Code)
	}
	w = request(s, "POST", templates, string(payload), token, origin, true)
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &seeded) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	id, _ := seeded.Template["id"].(string)
	w = request(s, "POST", "/admin/api/profiles", `{"name":"New","templateId":"`+id+`"}`, token, origin, true)
	var created struct {
		Profile struct{ ID string }
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &created) != nil {
		t.Fatal(w.Code, w.Body.String())
	}
	raw, err := s.repository.Raw(created.Profile.ID)
	if err != nil || !strings.Contains(raw, "DOMAIN-SUFFIX,binance.com,Binance") ||
		!strings.Contains(raw, "IP-CIDR,192.0.2.0/24,Binance,no-resolve") ||
		!strings.Contains(raw, "MATCH,DIRECT") {
		t.Fatal("new profile is missing scoped rules", err)
	}
	if w := request(s, "DELETE", templates, `{"id":"`+id+`"}`, token, origin, true); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if after, err := s.repository.Raw(created.Profile.ID); err != nil || after != raw {
		t.Fatal("deleting a template affected an existing profile", err)
	}
}
