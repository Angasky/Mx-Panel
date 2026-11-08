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

func TestBandwidthOwnershipSurvivesRejectedServerIdentityChanges(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	public, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	id := value(public["id"])
	m.mu.Lock()
	data, err := m.load()
	if err == nil {
		row, e := find(data, id)
		err = e
		if err == nil {
			row["bandwidths"] = Record{"1": Record{"port": 24443, "protocols": []any{"tcp"}, "uploadKbps": 1000, "downloadKbps": 1000}}
			err = m.flush(data)
		}
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "remote", "servers.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []Record{
		{"host": "198.51.100.11"}, {"sshPort": 2222}, {"installType": "xray"},
		{"fingerprint": "SHA256:" + base64.RawStdEncoding.EncodeToString([]byte(strings.Repeat("x", 32)))},
	} {
		change["id"] = id
		if _, err := m.Save(change); err == nil {
			t.Fatal("identity change orphaned policing", change)
		}
		after, err := os.ReadFile(path)
		if err != nil || string(after) != string(before) {
			t.Fatal("rejected edit modified durable state", err)
		}
	}
	if _, err := m.Save(Record{"id": id, "name": "renamed", "sshPassword": "replacement-password"}); err != nil {
		t.Fatal("unrelated edit blocked", err)
	}
	row, err := m.Record(id)
	if err != nil {
		t.Fatal(err)
	}
	policies, err := inboundObject(row["bandwidths"])
	if err != nil || len(policies) != 1 {
		t.Fatal("policing metadata lost", err)
	}
}

func TestServerEndpointsNormalizeIndependently(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	payload := serverPayload()
	payload["host"] = " [2001:db8::10] "
	payload["domain"] = " 你好.example.com. "
	payload["nodeAddress"] = " EDGE.Example.COM. "
	record, err := m.Save(payload)
	if err != nil {
		t.Fatal(err)
	}
	if record["host"] != "2001:db8::10" || record["domain"] != "xn--6qq79v.example.com" || record["nodeAddress"] != "edge.example.com" {
		t.Fatal("endpoint normalization", record)
	}
	if nodeAddress(record) != "edge.example.com" || record["panelAddress"] != payload["panelAddress"] {
		t.Fatal("endpoint roles mixed")
	}
	record, err = m.Save(Record{"id": record["id"], "nodeAddress": "[2001:db8::20]"})
	if err != nil || nodeAddress(record) != "2001:db8::20" {
		t.Fatal(record, err)
	}
	for _, field := range []string{"domain", "nodeAddress"} {
		for _, value := range []string{"-bad.example.com", "bad..example.com", "bad.example.com/path", "127.0.0.1"} {
			if _, err := m.Save(Record{"id": record["id"], field: value}); err == nil {
				t.Fatal("invalid endpoint accepted", field, value)
			}
		}
	}
}

func TestTrailingRegistryJSONIsNeverRewritten(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"servers":[],"jobs":[]} {"servers":[{"id":"hidden"}]}`)
	if err = os.WriteFile(m.path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Save(serverPayload()); err == nil {
		t.Fatal("ambiguous registry accepted")
	}
	after, err := os.ReadFile(m.path)
	if err != nil || string(after) != string(raw) {
		t.Fatal("corrupt registry overwritten", err)
	}
}

func TestServerListShowsOnlyCurrentInstallTypeJobs(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{"3x-ui", "xray", "sing-box"} {
		data := Record{"servers": []any{Record{"id": "s", "installType": kind}}, "jobs": []any{
			Record{"id": "legacy", "serverId": "s", "status": "interrupted"},
			Record{"id": "xray", "serverId": "s", "installType": "xray", "status": "success"},
			Record{"id": "other-server", "serverId": "other", "installType": kind, "status": "failed"},
			Record{"id": "other-type", "serverId": "s", "installType": "x-ui", "status": "failed"},
		}}
		if err := m.flush(data); err != nil {
			t.Fatal(err)
		}
		list, err := m.List()
		if err != nil || len(list) != 1 {
			t.Fatal(list, err)
		}
		job, exists := list[0]["job"].(Record)
		switch kind {
		case "3x-ui":
			if !exists || job["id"] != "legacy" {
				t.Fatal(kind, list)
			}
		case "xray":
			if !exists || job["id"] != "xray" {
				t.Fatal(kind, list)
			}
		case "sing-box":
			if exists {
				t.Fatal("unrelated job shown", list)
			}
		}
	}
}

func TestAmbiguousServerRegistryBlocksReadSaveAndForget(t *testing.T) {
	for _, servers := range []string{
		`[{"id":"same","host":"198.51.100.1"},{"id":"same","host":"198.51.100.2"}]`,
		`[{"id":"same"},null]`, `[{"id":"same"},{"id":42}]`, `[{"id":"same"},{"id":" "}]`,
	} {
		m, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		raw := []byte(`{"servers":` + servers + `,"jobs":[]}`)
		if err = os.WriteFile(m.path, raw, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err = m.Record("same"); err == nil {
			t.Fatal("ambiguous server selected")
		}
		if _, err = m.List(); err == nil {
			t.Fatal("ambiguous registry listed")
		}
		if _, err = m.Save(serverPayload()); err == nil {
			t.Fatal("ambiguous registry rewritten")
		}
		called := false
		if _, err = m.ForgetServer("same", func(_ Record, commit func() error) (Record, error) { called = true; return Record{}, commit() }); err == nil || called {
			t.Fatal("ambiguous registry detached")
		}
		after, err := os.ReadFile(m.path)
		if err != nil || string(after) != string(raw) {
			t.Fatal("registry changed", err)
		}
	}
}
