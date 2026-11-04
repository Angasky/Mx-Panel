package remote

import (
	"errors"
	"os"
	"testing"
)

func TestForgetServerLocalOnlyAndBusyGuards(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	a, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	second := serverPayload()
	second["host"] = "198.51.100.11"
	b, err := m.Save(second)
	if err != nil {
		t.Fatal(err)
	}
	id := value(a["id"])
	data, _ := m.load()
	data["jobs"] = []any{Record{"serverId": id, "status": "running"}, Record{"serverId": b["id"], "status": "done"}}
	if err = m.flush(data); err != nil {
		t.Fatal(err)
	}
	calls := 0
	detach := func(_ Record, commit func() error) (Record, error) {
		calls++
		return Record{"remotePreserved": true}, commit()
	}
	if _, err = m.ForgetServer(id, detach); err == nil || calls != 0 {
		t.Fatal("running job bypassed")
	}
	data["jobs"].([]any)[0].(Record)["status"] = "done"
	if err = m.flush(data); err != nil {
		t.Fatal(err)
	}
	m.operations = map[string]chan struct{}{id: make(chan struct{}, 1)}
	m.operations[id] <- struct{}{}
	if _, err = m.ForgetServer(id, detach); err == nil || calls != 0 {
		t.Fatal("active operation bypassed")
	}
	<-m.operations[id]
	before, _ := os.ReadFile(m.path)
	failure := errors.New("binding transaction failed")
	if _, err = m.ForgetServer(id, func(Record, func() error) (Record, error) { return nil, failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(m.path)
	if string(before) != string(after) {
		t.Fatal("failed detachment changed registry")
	}
	if _, err = m.ForgetServer(id, func(Record, func() error) (Record, error) { return Record{}, nil }); err == nil {
		t.Fatal("uncommitted removal reported success")
	}
	m.panels = map[string]*cachedPanel{id: {}}
	if _, err = m.ForgetServer(id, detach); err != nil {
		t.Fatal(err)
	}
	if _, err = m.Record(id); err == nil {
		t.Fatal("server remains registered")
	}
	if _, err = m.Record(value(b["id"])); err != nil {
		t.Fatal("other server removed")
	}
	data, _ = m.load()
	if len(data["jobs"].([]any)) != 1 || m.panels[id] != nil || m.operations[id] != nil {
		t.Fatal("local cleanup incomplete")
	}
}

func TestForgetThenRegisterSameEndpointAndRetry(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	payload := serverPayload()
	payload["host"] = "2001:db8:0:0::10"
	old, err := m.Save(payload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.ForgetServer(value(old["id"]), func(_ Record, commit func() error) (Record, error) {
		return Record{}, commit()
	}); err != nil {
		t.Fatal(err)
	}
	m, err = Open(root)
	if err != nil {
		t.Fatal(err)
	}
	added, err := m.Save(payload)
	if err != nil || added["id"] == old["id"] {
		t.Fatal("re-registration should create a new record", err)
	}
	payload["host"], payload["sshPort"] = "2001:db8::10", "22"
	retried, err := m.Save(payload)
	if err != nil || retried["id"] != added["id"] {
		t.Fatal("equivalent retry should return the existing ID", err)
	}
	payload["sshPassword"] = "changed-password"
	if _, err := m.Save(payload); err == nil {
		t.Fatal("conflicting credentials should require an explicit edit")
	}
	servers, err := m.List()
	if err != nil || len(servers) != 1 {
		t.Fatal("server was duplicated", err)
	}
}
