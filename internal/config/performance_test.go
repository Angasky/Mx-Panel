package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// This benchmark retains the real backup, mirrored writes and fsync policy.
// Use CPU and allocation profiles to distinguish YAML work from storage latency.
func BenchmarkChangedSave(b *testing.B) {
	for _, count := range []int{100, 1000} {
		b.Run(fmt.Sprint(count), func(b *testing.B) {
			root := b.TempDir()
			primary := filepath.Join(root, "primary.yaml")
			mirror := filepath.Join(root, "mirror.yaml")
			nodes := make([]any, count)
			names := make([]any, count)
			for i := range nodes {
				n := node(fmt.Sprintf("Node-%04d", i))
				n["type"] = "trojan"
				n["sni"] = "example.com"
				nodes[i] = n
				names[i] = n["name"]
			}
			doc := Document{"proxies": nodes, "proxy-groups": []any{Document{"name": "Proxy", "type": "select", "proxies": names}}, "rules": []any{"MATCH,Proxy"}}
			raw, err := yaml.Marshal(doc)
			if err != nil {
				b.Fatal(err)
			}
			for _, path := range []string{primary, mirror} {
				if err = os.WriteFile(path, raw, 0600); err != nil {
					b.Fatal(err)
				}
			}
			index, _ := json.Marshal(Document{"profiles": []any{Document{"id": "clash", "files": []string{primary, mirror}}}})
			if err = os.WriteFile(filepath.Join(root, "profiles.json"), index, 0600); err != nil {
				b.Fatal(err)
			}
			repository := &Repository{Root: root}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				err = repository.Mutate("clash", func(doc Document) error {
					rows(doc, "proxies")[0].(Document)["password"] = fmt.Sprintf("password-%d", i)
					return nil
				})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
