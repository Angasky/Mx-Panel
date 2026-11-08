package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// Exercise cold configuration loads concurrent with writes across independent
// subscriptions; verify each mirror and update count after all requests finish.
func TestMultipleProfilesColdReadsAndWrites(t *testing.T) {
	root := t.TempDir()
	profiles := []any{}
	const count = 12
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("profile-%02d", i)
		files := []string{filepath.Join(root, id+".yaml"), filepath.Join(root, id+"-mirror.yaml")}
		for _, file := range files {
			if err := os.WriteFile(file, []byte("proxies: []\nproxy-groups: []\nrules: []\n"), 0600); err != nil {
				t.Fatal(err)
			}
		}
		profiles = append(profiles, Document{"id": id, "name": id, "files": files})
	}
	raw, _ := json.Marshal(Document{"profiles": profiles})
	if err := os.WriteFile(filepath.Join(root, "profiles.json"), raw, 0600); err != nil {
		t.Fatal(err)
	}
	repository := &Repository{Root: root}
	var group sync.WaitGroup
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("profile-%02d", i)
		for reader := 0; reader < 3; reader++ {
			group.Go(func() {
				for n := 0; n < 10; n++ {
					if _, err := repository.Snapshot(id); err != nil {
						t.Error(err)
					}
				}
			})
		}
		group.Go(func() {
			for n := 0; n < 10; n++ {
				if err := repository.Mutate(id, func(doc Document) error {
					return EditNode(doc, "POST", Document{"config": node(fmt.Sprintf("node-%02d", n))})
				}); err != nil {
					t.Error(err)
				}
			}
		})
	}
	group.Wait()
	reopened := &Repository{Root: root}
	for i := 0; i < count; i++ {
		id := fmt.Sprintf("profile-%02d", i)
		snap, err := reopened.Snapshot(id)
		if err != nil || len(snap["nodes"].([]any)) != 10 {
			t.Fatal("profile lost updates", id, err)
		}
		first, err := os.ReadFile(filepath.Join(root, id+".yaml"))
		if err != nil {
			t.Fatal(err)
		}
		second, err := os.ReadFile(filepath.Join(root, id+"-mirror.yaml"))
		if err != nil || string(first) != string(second) {
			t.Fatal("profile mirror diverged", id, err)
		}
	}
}
