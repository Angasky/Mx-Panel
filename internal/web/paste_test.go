package web

import (
	"encoding/json"
	"github.com/Angasky/dingzhi-ban/internal/links"
	"testing"
)

func TestMarkdownPasteImportsMultipleLinksWithOriginalFailureLine(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	body, _ := json.Marshal(map[string]any{"links": "```text\r\n[First](trojan://secret%29@example.net:443#First)[Second](hy2://secret@example.net:443#Second)\r\n`http://example.net:80#Third`\r\nnot-a-node\r\n```"})
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct {
		Total, Added int
		Failed       []struct{ Line int }
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Total != 4 || result.Added != 3 || len(result.Failed) != 1 || result.Failed[0].Line != 4 {
		t.Fatal("paste contract mismatch", w.Code, w.Body.String())
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=First", "", token, "", true)
	var share struct{ URI string }
	if json.Unmarshal(w.Body.Bytes(), &share) != nil || w.Code != 200 {
		t.Fatal("share failed")
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["password"] != "secret)" {
		t.Fatal("Markdown changed password", err)
	}
}

func TestLegacyEscapedPasteSavedAndShared(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	body, _ := json.Marshal(map[string]any{"links": "'trojan\\://pass%5C%40word\\@example\\.net:443#Legacy'\ninvalid"})
	w := request(s, "POST", "/admin/api/import-node", string(body), token, "https://panel.test", true)
	var result struct {
		Total, Added int
		Failed       []struct{ Line int }
	}
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || w.Code != 200 || result.Total != 2 || result.Added != 1 || len(result.Failed) != 1 || result.Failed[0].Line != 2 {
		t.Fatal("import contract", w.Code, w.Body.String())
	}
	w = request(s, "GET", "/admin/api/nodes/share?name=Legacy", "", token, "", true)
	var share struct{ URI string }
	if json.Unmarshal(w.Body.Bytes(), &share) != nil || w.Code != 200 {
		t.Fatal("share failed")
	}
	node, err := links.Parse(share.URI)
	if err != nil || node["password"] != "pass\\@word" || node["server"] != "example.net" {
		t.Fatal("saved credential changed", err)
	}
}

func TestPythonBatchLinkAliasDefaultsNamesAndRename(t *testing.T) {
	s := fixture(t)
	token := login(t, s)
	if err := s.repository.Mutate("clash", func(doc map[string]any) error {
		doc["proxy-groups"] = []any{map[string]any{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT"}}, map[string]any{"name": "Fallback", "type": "fallback", "proxies": []any{"DIRECT"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	body := `{"link":"http://example.net:80#Imported\nhttp://example.net:80#Imported"}`
	w := request(s, "POST", "/admin/api/import-node", body, token, "https://panel.test", true)
	var result struct {
		Added   int
		Names   []string
		Renamed []map[string]string
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &result) != nil || result.Added != 2 || len(result.Names) != 2 || result.Names[1] != "Imported-02" || result.Renamed[0]["to"] != "Imported-02" {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot, err := s.repository.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	groups := snapshot["groups"].([]any)
	for _, item := range groups {
		group := item.(map[string]any)["config"].(map[string]any)
		members := group["proxies"].([]any)
		if group["name"] == "Proxy" && len(members) != 3 {
			t.Fatal("omitted addToGroups did not use Python default")
		}
		if group["name"] == "Fallback" && len(members) != 1 {
			t.Fatal("automatic import changed fallback")
		}
	}
	w = request(s, "POST", "/admin/api/import-node", `{"links":"http://example.net:80#Excluded","addToGroups":false}`, token, "https://panel.test", true)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	snapshot, err = s.repository.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range snapshot["groups"].([]any) {
		group := item.(map[string]any)["config"].(map[string]any)
		for _, member := range group["proxies"].([]any) {
			if member == "Excluded" {
				t.Fatal("explicit false ignored")
			}
		}
	}
}
