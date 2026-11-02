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
