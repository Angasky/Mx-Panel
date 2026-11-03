package web

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCheckDataReadsAllProfilesWithoutChangingFiles(t *testing.T) {
	s := fixture(t)
	path := filepath.Join(s.options.Root, "fixture.yaml")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.CheckData(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("check changed configuration")
	}
	if err = os.WriteFile(path, []byte("proxies: ["), 0600); err != nil {
		t.Fatal(err)
	}
	if err = s.CheckData(); err == nil {
		t.Fatal("invalid subscription accepted")
	}
}
