package config

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func sourceFixture(t *testing.T) (*Repository, string, string) {
	r, p, m := fixture(t)
	if err := r.Mutate("clash", func(doc Document) error {
		doc["proxies"] = []any{node("A")}
		doc["proxy-groups"] = []any{Document{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT", "A"}}, Document{"name": "Other", "type": "select", "proxies": []any{"DIRECT"}}, Document{"name": "🛑 广告拦截", "type": "select", "proxies": []any{"REJECT"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return r, p, m
}

func TestSourceImportRenameSkipReplaceAndGroups(t *testing.T) {
	r, primary, mirror := sourceFixture(t)
	incoming := []map[string]any{node("A"), node("A"), node("Proxy")}
	incoming[0]["password"] = "external"
	incoming[0]["custom"] = Document{"keep": true}
	incoming[0]["dialer-proxy"] = "foreign"
	result, err := r.ImportSubscription("clash", incoming, "rename", []any{"Proxy"}, 2)
	if err != nil {
		t.Fatal(err)
	}
	if result["added"] != 3 || result["replaced"] != 0 || result["skipped"] != 2 {
		t.Fatal(result)
	}
	snapshot, _ := r.Snapshot("clash")
	nodes := snapshot["nodes"].([]any)
	if len(nodes) != 4 || nodes[1].(Document)["name"] != "A-02" || nodes[2].(Document)["name"] != "A-03" || nodes[3].(Document)["name"] != "Proxy-02" {
		t.Fatal("rename collision handling failed", nodes)
	}
	added := nodes[1].(Document)["config"].(Document)
	if added["dialer-proxy"] != nil || added["custom"].(Document)["keep"] != true {
		t.Fatal("foreign reference or unknown field lost")
	}
	if incoming[0]["name"] != "A" || incoming[0]["dialer-proxy"] != "foreign" {
		t.Fatal("source document mutated")
	}
	groups := snapshot["groups"].([]any)
	if len(groups[0].(Document)["config"].(Document)["proxies"].([]any)) != 5 || len(groups[1].(Document)["config"].(Document)["proxies"].([]any)) != 1 || len(groups[2].(Document)["config"].(Document)["proxies"].([]any)) != 1 {
		t.Fatal("group membership incorrect", groups)
	}
	a, _ := os.ReadFile(primary)
	b, _ := os.ReadFile(mirror)
	if !bytes.Equal(a, b) {
		t.Fatal("mirrors diverged")
	}
	result, err = r.ImportSubscription("clash", []map[string]any{node("A"), node("B")}, "skip", nil, 1)
	if err != nil || result["added"] != 1 || result["skipped"] != 2 {
		t.Fatal(result, err)
	}
	replacement := node("A")
	replacement["password"] = "replaced"
	result, err = r.ImportSubscription("clash", []map[string]any{replacement}, "replace", []any{"Other"}, 0)
	if err != nil || result["replaced"] != 1 {
		t.Fatal(result, err)
	}
	snapshot, _ = r.Snapshot("clash")
	if snapshot["nodes"].([]any)[0].(Document)["config"].(Document)["password"] != "replaced" {
		t.Fatal("replace not committed")
	}
}

func TestSourceImportFailuresAreAtomic(t *testing.T) {
	for _, tc := range []struct {
		mode   string
		groups any
		nodes  []map[string]any
	}{
		{"skip", nil, []map[string]any{node("A")}},
		{"invalid", nil, []map[string]any{node("B")}},
		{"rename", []any{"deleted-group"}, []map[string]any{node("B")}},
		{"rename", []any{"🛑 广告拦截"}, []map[string]any{node("B")}},
		{"rename", "bad", []map[string]any{node("B")}},
		{"rename", nil, []map[string]any{node("B"), {"name": "invalid"}}},
		{"rename", nil, []map[string]any{node(strings.Repeat("a", 1024)), node(strings.Repeat("a", 1024))}},
	} {
		r, primary, _ := sourceFixture(t)
		before, _ := os.ReadFile(primary)
		backups, _ := r.Backups("clash")
		if _, err := r.ImportSubscription("clash", tc.nodes, tc.mode, tc.groups, 0); err == nil {
			t.Fatal("bad batch accepted", tc.mode)
		}
		after, _ := os.ReadFile(primary)
		later, _ := r.Backups("clash")
		if !bytes.Equal(before, after) || len(backups) != len(later) {
			t.Fatal("rejected batch changed disk")
		}
	}
}

func TestSourceImportProtectsOwnedAndFailoverNodes(t *testing.T) {
	r, primary, _ := sourceFixture(t)
	if err := r.UpdateState("clash", func(p Document) error {
		p["remoteNodes"] = []any{Document{"status": "active", "scope": "user", "importedNames": []any{"A"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	replacement := node("A")
	replacement["password"] = "foreign"
	if _, err := r.ImportSubscription("clash", []map[string]any{replacement}, "replace", nil, 0); err == nil {
		t.Fatal("owned node overwritten")
	}
	if _, err := r.ImportSubscription("clash", []map[string]any{replacement}, "rename", nil, 0); err != nil {
		t.Fatal(err)
	}
	if err := r.UpdateState("clash", func(p Document) error {
		p["remoteNodes"] = []any{}
		p["failovers"] = []any{Document{"name": "protected", "entries": []any{"A"}}}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(primary)
	if _, err := r.ImportSubscription("clash", []map[string]any{replacement}, "replace", nil, 0); err == nil {
		t.Fatal("failover node overwritten")
	}
	after, _ := os.ReadFile(primary)
	if !bytes.Equal(before, after) {
		t.Fatal("protected node changed")
	}
}

func TestSourceImportMirrorFailureRestoresAndBoundsResult(t *testing.T) {
	r, primary, _ := sourceFixture(t)
	before, _ := os.ReadFile(primary)
	index, _ := json.Marshal(Document{"profiles": []any{Document{"id": "clash", "files": []string{primary, filepath.Join(r.Root, "absent", "mirror.yaml")}}}})
	if err := os.WriteFile(filepath.Join(r.Root, "profiles.json"), index, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := r.ImportSubscription("clash", []map[string]any{node("B")}, "rename", nil, 0); err == nil {
		t.Fatal("mirror failure ignored")
	}
	after, _ := os.ReadFile(primary)
	if !bytes.Equal(before, after) {
		t.Fatal("failed batch partially committed")
	}
	r, _, _ = sourceFixture(t)
	many := make([]map[string]any, 100)
	for i := range many {
		many[i] = node("same")
	}
	result, err := r.ImportSubscription("clash", many, "rename", []any{}, 0)
	if err != nil || result["added"] != 100 || len(result["names"].([]any)) != 30 {
		t.Fatal(result, err)
	}
}
