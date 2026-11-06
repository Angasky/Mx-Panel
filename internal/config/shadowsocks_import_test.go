package config

import (
	"bytes"
	"encoding/base64"
	"os"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/links"
)

func TestSS2022ImportEditExport(t *testing.T) {
	for _, size := range []int{16, 32} {
		method := "2022-blake3-aes-256-gcm"
		if size == 16 {
			method = "2022-blake3-aes-128-gcm"
		}
		t.Run(method, func(t *testing.T) {
			r, primary, mirror := sourceFixture(t)
			key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, size))
			user := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, size))
			n := map[string]any{"name": "SS2022", "type": "ss", "server": "example.com", "port": 23456, "cipher": method, "password": key + ":" + user}
			uri, err := links.Export(n)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := links.Parse(uri)
			if err != nil {
				t.Fatal(err)
			}
			if _, err = r.ImportSubscription("clash", []map[string]any{parsed}, "rename", nil, 0); err != nil {
				t.Fatal(err)
			}
			edited := key + ":" + base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, size))
			parsed["password"] = edited
			if err = r.Mutate("clash", func(doc Document) error {
				return EditNode(doc, "PUT", map[string]any{"oldName": "SS2022", "config": parsed})
			}); err != nil {
				t.Fatal(err)
			}
			snapshot, err := r.Snapshot("clash")
			if err != nil {
				t.Fatal(err)
			}
			stored := snapshot["nodes"].([]any)[1].(Document)["config"].(Document)
			uri, err = links.Export(stored)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := links.Parse(uri)
			if err != nil || roundtrip["password"] != edited {
				t.Fatal("edited credentials not preserved", err)
			}
			before, err := os.ReadFile(primary)
			if err != nil {
				t.Fatal(err)
			}
			for _, bad := range []string{key + ":", ":" + user, key + ":" + user + ":" + user, key + ":" + strings.TrimRight(user, "="), key + ":" + user + "\n"} {
				parsed["password"] = bad
				if _, err = r.ImportSubscription("clash", []map[string]any{parsed}, "replace", nil, 0); err == nil {
					t.Fatal("invalid password imported")
				}
				if err = r.Mutate("clash", func(doc Document) error {
					return EditNode(doc, "PUT", map[string]any{"oldName": "SS2022", "config": parsed})
				}); err == nil {
					t.Fatal("invalid password edited")
				}
				for _, path := range []string{primary, mirror} {
					after, err := os.ReadFile(path)
					if err != nil || !bytes.Equal(before, after) {
						t.Fatal("failed operation changed subscription", err)
					}
				}
			}
		})
	}
}
