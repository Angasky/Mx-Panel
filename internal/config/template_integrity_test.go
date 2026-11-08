package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestBlankTemplateRejectsTrailingYAMLWithoutCreatingProfile(t *testing.T) {
	r, _, _ := fixture(t)
	directory := filepath.Join(r.Root, "templates")
	if err := os.MkdirAll(directory, 0700); err != nil {
		t.Fatal(err)
	}
	index := filepath.Join(r.Root, "profiles.json")
	before, err := os.ReadFile(index)
	if err != nil {
		t.Fatal(err)
	}
	for _, suffix := range []string{"---\nrules: [MATCH,REJECT]\n", "---\n[broken"} {
		if err := os.WriteFile(filepath.Join(directory, "clash.yaml"), []byte("proxies: []\nproxy-groups: []\nrules: []\n"+suffix), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := r.CreateProfile(Document{"name": "new", "templateId": "blank"}); err == nil {
			t.Fatal("accepted trailing YAML")
		}
		after, err := os.ReadFile(index)
		if err != nil || string(before) != string(after) {
			t.Fatal("index changed", err)
		}
		files, err := filepath.Glob(filepath.Join(r.Root, "profiles", "*"))
		if err != nil || len(files) != 0 {
			t.Fatal("created profile files", files, err)
		}
	}
}

func TestMalformedPolicyTemplateRegistryIsNotSilentlyReplaced(t *testing.T) {
	for _, templates := range []any{
		Document{"legacy": "preserve"}, "preserve", []any{nil},
		[]any{Document{"id": "policy-a"}, Document{"id": "policy-a"}},
		[]any{Document{"name": "missing ID"}},
	} {
		r, _, _ := fixture(t)
		index, err := r.index()
		if err != nil {
			t.Fatal(err)
		}
		index["policyTemplates"] = templates
		if err = r.writeIndex(index); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(r.Root, "profiles.json")
		before, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = r.PolicyTemplates("clash", "", ""); err == nil {
			t.Fatal("invalid templates listed as empty")
		}
		if _, err = r.SavePolicyTemplate("POST", Document{"name": "new", "groups": []any{}, "rules": []any{"MATCH,DIRECT"}}); err == nil {
			t.Fatal("invalid templates overwritten")
		}
		after, err := os.ReadFile(path)
		if err != nil || string(before) != string(after) {
			t.Fatal("original registry changed", err)
		}
	}
}
