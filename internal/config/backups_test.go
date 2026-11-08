package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBackupsAreProfileScopedAndRestoreCreatesSafetyCopy(t *testing.T) {
	r, _, _ := fixture(t)
	if err := r.Mutate("clash", func(doc Document) error { return EditNode(doc, "POST", map[string]any{"config": node("A")}) }); err != nil {
		t.Fatal(err)
	}
	backups, err := r.Backups("clash")
	if err != nil || len(backups) != 1 {
		t.Fatal("profile backup not listed")
	}
	before := backups[0]["name"].(string)
	if err = r.Restore("clash", before); err != nil {
		t.Fatal(err)
	}
	snapshot, err := r.Snapshot("clash")
	if err != nil || len(snapshot["nodes"].([]any)) != 0 {
		t.Fatal("backup restore failed")
	}
	backups, err = r.Backups("clash")
	if err != nil || len(backups) != 2 {
		t.Fatal("restore did not create before-restore backup")
	}
	created, err := r.CreateProfile(map[string]any{"name": "other", "templateId": "blank"})
	if err != nil {
		t.Fatal(err)
	}
	if err = r.Restore(created["id"].(string), before); err == nil {
		t.Fatal("cross-profile restore accepted")
	}
	if err = r.Restore("clash", "../"+before); err == nil {
		t.Fatal("backup path traversal accepted")
	}
}

func TestSuccessfulSavePrunesOldBackupsWithoutFollowingLinks(t *testing.T) {
	r, primary, _ := fixture(t)
	directory := filepath.Join(r.Root, "backups")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Add(-time.Hour)
	for i := 0; i < 105; i++ {
		path := filepath.Join(directory, fmt.Sprintf("clash.old-%03d.yaml", i))
		if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(path, stamp.Add(time.Duration(i)*time.Second), stamp.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"notes.txt"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("keep"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Mkdir(filepath.Join(directory, "directory.yaml"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(primary, filepath.Join(directory, "clash.link.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := r.Mutate("clash", func(doc Document) error { return errors.New("rejected") }); err == nil {
		t.Fatal("rejection lost")
	}
	if _, err := os.Stat(filepath.Join(directory, "clash.old-000.yaml")); err != nil {
		t.Fatal("rejected edit pruned backups")
	}
	if err := r.Mutate("clash", func(doc Document) error { return EditNode(doc, "POST", Document{"config": node("retention")}) }); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, entry := range entries {
		if entry.Type().IsRegular() && strings.HasSuffix(entry.Name(), ".yaml") {
			count++
		}
	}
	if count != 100 {
		t.Fatal("unbounded backup history", count)
	}
	for _, name := range []string{"notes.txt", "directory.yaml", "clash.link.yaml", "clash.old-104.yaml"} {
		if _, err := os.Lstat(filepath.Join(directory, name)); err != nil {
			t.Fatal("unexpected cleanup", name, err)
		}
	}
	if _, err := os.Stat(filepath.Join(directory, "clash.old-005.yaml")); !os.IsNotExist(err) {
		t.Fatal("old backups not removed")
	}
	if err := r.Restore("clash", "clash.link.yaml"); err == nil {
		t.Fatal("symlink restore accepted")
	}
}
