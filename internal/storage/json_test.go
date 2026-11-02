package storage

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentTransactionsAndNumericPrecision(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profiles.json")
	original := []byte(`{"count":0,"used":9007199254740993,"profiles":[{"id":"old","unknown":{"retain":true}}]}`)
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	store := New(path)
	var group sync.WaitGroup
	for i := 0; i < 40; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := store.Update(func(doc map[string]any) error {
				n, err := doc["count"].(json.Number).Int64()
				if err != nil {
					return err
				}
				doc["count"] = n + 1
				return nil
			}); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	got, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if got["count"].(json.Number).String() != "40" || got["used"].(json.Number).String() != "9007199254740993" {
		t.Fatal("lost update or numeric precision")
	}
	before, _ := os.ReadFile(path)
	err = store.Update(func(doc map[string]any) error { delete(doc, "profiles"); return errors.New("reject") })
	if err == nil {
		t.Fatal("expected rejection")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(before) {
		t.Fatal("rejected transaction changed data")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("temporary files leaked")
	}
}
