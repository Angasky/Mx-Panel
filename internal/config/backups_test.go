package config

import "testing"

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
