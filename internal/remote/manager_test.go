package remote

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func serverPayload() Record {
	return Record{"name": "fixture", "host": "198.51.100.10", "sshPort": 22, "sshUser": "root", "sshPassword": "sample-ssh-password", "fingerprint": "SHA256:" + base64.RawStdEncoding.EncodeToString(make([]byte, 32)), "installType": "3x-ui", "connectionMode": "existing", "panelUser": "admin", "panelPassword": "sample-panel-password", "panelAddress": "https://panel.example.com:13145/path/"}
}
func TestEncryptedServerPersistenceAndPublicProjection(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := serverPayload()
	public, err := m.Save(payload)
	if err != nil {
		t.Fatal(err)
	}
	id := value(public["id"])
	if public["panelPort"] != 13145 || public["panelPath"] != "/path/" {
		t.Fatal("panel address normalization failed")
	}
	raw, err := os.ReadFile(filepath.Join(root, "remote", "servers.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "sample-ssh-password") || strings.Contains(string(raw), "sample-panel-password") {
		t.Fatal("plaintext credentials persisted")
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	record, err := reopened.Record(id)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"sshPassword", "panelPassword"} {
		plain, err := reopened.Secret(record, key)
		if err != nil || plain != payload[key] {
			t.Fatal("Fernet compatibility failed")
		}
	}
	updated, err := reopened.Save(Record{"id": id, "name": "renamed", "sshPassword": "", "panelPassword": ""})
	if err != nil {
		t.Fatal(err)
	}
	if updated["name"] != "renamed" {
		t.Fatal("metadata update failed")
	}
	list, err := reopened.List()
	if err != nil || len(list) != 1 {
		t.Fatal("server list failed")
	}
	for _, key := range []string{"sshPassword", "panelPassword", "coreConfig", "coreState"} {
		if _, ok := list[0][key]; ok {
			t.Fatal("private field exposed", key)
		}
	}
	before, _ := os.ReadFile(filepath.Join(root, "remote", "servers.json"))
	if _, err = reopened.Save(Record{"id": id, "sshPort": ""}); err == nil {
		t.Fatal("zero SSH port accepted")
	}
	after, _ := os.ReadFile(filepath.Join(root, "remote", "servers.json"))
	if string(before) != string(after) {
		t.Fatal("rejected update persisted")
	}
}
func TestMissingLegacyKeyDoesNotGenerateReplacement(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "remote")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "servers.json"), []byte(`{"servers":[{"id":"legacy"}],"jobs":[]}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(root); err == nil {
		t.Fatal("missing legacy key accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.key")); !os.IsNotExist(err) {
		t.Fatal("legacy key silently replaced")
	}
}
