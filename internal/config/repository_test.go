package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func fixture(t *testing.T) (*Repository, string, string) {
	t.Helper()
	root := t.TempDir()
	primary := filepath.Join(root, "primary.yaml")
	mirror := filepath.Join(root, "mirror.yaml")
	data, _ := json.Marshal(map[string]any{"profiles": []any{map[string]any{"id": "clash", "name": "test", "files": []string{primary, mirror}}}})
	if err := os.WriteFile(filepath.Join(root, "profiles.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{primary, mirror} {
		if err := os.WriteFile(p, []byte("proxies: []\nproxy-groups: []\nrules: []\ncustom: 9007199254740993\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return &Repository{Root: root}, primary, mirror
}
func node(name string) map[string]any {
	return map[string]any{"name": name, "type": "hysteria2", "server": "vpn.example.com", "port": 24443, "password": "secret"}
}
func TestConcurrentSaveAndMirrorRollback(t *testing.T) {
	r, primary, mirror := fixture(t)
	var group sync.WaitGroup
	for i := 0; i < 20; i++ {
		group.Add(1)
		go func(i int) {
			defer group.Done()
			err := r.Mutate("clash", func(doc Document) error {
				return EditNode(doc, "POST", map[string]any{"config": node(string(rune('A' + i)))})
			})
			if err != nil {
				t.Error(err)
			}
		}(i)
	}
	group.Wait()
	snapshot, err := r.Snapshot("clash")
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot["nodes"].([]any)) != 20 {
		t.Fatal("lost node updates")
	}
	a, _ := os.ReadFile(primary)
	b, _ := os.ReadFile(mirror)
	if string(a) != string(b) {
		t.Fatal("mirrors differ")
	}
	// Replace mirror with a directory: reads must fail before changing the primary.
	if err = os.Remove(mirror); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(mirror, 0700); err != nil {
		t.Fatal(err)
	}
	err = r.Mutate("clash", func(doc Document) error { doc["custom"] = "changed"; return nil })
	if err == nil {
		t.Fatal("mirror error ignored")
	}
	after, _ := os.ReadFile(primary)
	if string(a) != string(after) {
		t.Fatal("primary changed after failed mirror read")
	}
}
func TestFailedMirrorWriteRestoresPrimary(t *testing.T) {
	r, primary, _ := fixture(t)
	data, _ := json.Marshal(map[string]any{"profiles": []any{map[string]any{"id": "clash", "files": []string{primary, filepath.Join(r.Root, "absent-directory", "mirror.yaml")}}}})
	os.WriteFile(filepath.Join(r.Root, "profiles.json"), data, 0600)
	before, _ := os.ReadFile(primary)
	err := r.Mutate("clash", func(doc Document) error { doc["custom"] = "changed"; return nil })
	if err == nil {
		t.Fatal("write failure ignored")
	}
	after, _ := os.ReadFile(primary)
	if string(before) != string(after) {
		t.Fatal("primary rollback failed")
	}
}
func TestNodeRenameDeleteAndOrder(t *testing.T) {
	doc := Document{"proxies": []any{node("A"), node("B"), node("C")}, "proxy-groups": []any{map[string]any{"name": "Proxy", "type": "select", "proxies": []any{"DIRECT", "A", "Nested", "B", "C"}}}}
	if err := MoveNode(doc, map[string]any{"name": "C", "targetName": "A", "position": "before"}); err != nil {
		t.Fatal(err)
	}
	group := rows(doc, "proxy-groups")[0].(map[string]any)
	refs := group["proxies"].([]any)
	if refs[0] != "DIRECT" || refs[1] != "C" || refs[2] != "Nested" || refs[3] != "A" {
		t.Fatal("special group entries moved")
	}
	if err := EditNode(doc, "PUT", map[string]any{"oldName": "A", "config": node("renamed")}); err != nil {
		t.Fatal(err)
	}
	if group["proxies"].([]any)[3] != "renamed" {
		t.Fatal("rename references stale")
	}
	if err := EditNode(doc, "DELETE", map[string]any{"name": "renamed"}); err != nil {
		t.Fatal(err)
	}
	if len(group["proxies"].([]any)) != 4 {
		t.Fatal("deleted node reference remains")
	}
}
