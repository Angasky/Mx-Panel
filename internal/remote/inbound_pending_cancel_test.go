package remote

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPendingPanelCancelWaitsForLateCreationAndSurvivesRestart(t *testing.T) {
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
	record, _ := m.Record(id)
	request := strings.Repeat("a", 32)
	key, hash, _ := createRequestIdentity("clash", Record{"operationId": request})
	desired := Record{"port": 24001, "protocol": "vless", "enable": true, "settings": Record{"clients": []any{}, "decryption": "none"}, "streamSettings": Record{"network": "tcp", "security": "none"}}
	entry := Record{"scope": "clash", "serverId": id, "revision": createServerRevision(record), "requestHash": hash, "status": "sent", "desired": desired}
	if err = m.persistCreate(key, entry); err != nil {
		t.Fatal(err)
	}
	var live Record
	deletes := 0
	fixture := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/panel/api/inbounds/list":
			rows := []any{}
			if live != nil {
				rows = append(rows, live)
			}
			json.NewEncoder(w).Encode(Record{"success": true, "obj": rows})
		case "/panel/api/inbounds/del/7":
			deletes++
			live = nil
			json.NewEncoder(w).Encode(Record{"success": true})
		default:
			t.Error("unexpected request", r.URL.Path)
			http.Error(w, "unexpected", 500)
		}
	}))
	defer fixture.Close()
	base, _ := url.Parse(fixture.URL + "/")
	panel := newPanel(base, fixture.Client().Transport, Record{}, "", "token", NewPanelSession())
	if _, err = m.requestCreateCancel("clash", key); err != nil {
		t.Fatal(err)
	}
	guard := func(request, server string, inbound int, row Record) error {
		if request != strings.Repeat("a", 32) || server != id || inbound != 7 {
			t.Fatal("wrong target")
		}
		return nil
	}
	if err = m.cancelPanelCreate(context.Background(), panel, record, "clash", key, request, guard); err == nil {
		t.Fatal("absence incorrectly confirmed cancellation")
	}
	if deletes != 0 {
		t.Fatal("deleted before creation arrived")
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	m = reopened
	if err = m.persistCreate(key, entry); err == nil {
		t.Fatal("canceled request could be replayed")
	}
	raw, _ := json.Marshal(desired)
	live, _ = inboundObject(string(raw))
	live["id"], live["tag"] = 7, "inbound-7"
	if err = m.cancelPanelCreate(context.Background(), panel, record, "clash", key, request, guard); err != nil {
		t.Fatal(err)
	}
	saved, err := m.loadCreate(key)
	if err != nil || saved["status"] != "canceled" || live != nil || deletes != 1 {
		t.Fatal(saved, err, deletes)
	}
	if _, err = m.CancelPendingCreates(context.Background(), "clash", []string{request}, guard); err != nil || deletes != 1 {
		t.Fatal("completed cancellation replayed", err)
	}
}
func TestCancelUnknownRequestFencesNewReservations(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("b", 32)
	key, hash, _ := createRequestIdentity("clash", Record{"operationId": request})
	if _, err = m.CancelPendingCreates(context.Background(), "clash", []string{request}, func(string, string, int, Record) error { t.Fatal("remote call for unsent request"); return nil }); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(filepath.Dir(m.root))
	if err != nil {
		t.Fatal(err)
	}
	if err = reopened.reserveCoreCreate("server", key, "", "intent"); err == nil {
		t.Fatal("core reservation ignored cancel")
	}
	if err = reopened.persistCreate(key, Record{"serverId": "server", "scope": "clash", "revision": "revision", "requestHash": hash, "status": "prepared", "desired": Record{}}); err == nil {
		t.Fatal("panel reservation ignored cancel")
	}
}

func TestBatchCancellationFencesLaterPathsBeforeOfflineFirstPath(t *testing.T) {
	root := t.TempDir()
	m, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	public, err := m.Save(serverPayload())
	if err != nil {
		t.Fatal(err)
	}
	server := value(public["id"])
	record, _ := m.Record(server)
	requests := []string{strings.Repeat("c", 32), strings.Repeat("d", 32), strings.Repeat("e", 32)}
	keys := []string{}
	for i, request := range requests {
		key, hash, _ := createRequestIdentity("clash", Record{"operationId": request})
		keys = append(keys, key)
		if i == 2 {
			continue
		} // No write has been reserved for the final path.
		if err = m.persistCreate(key, Record{"scope": "clash", "serverId": server, "revision": createServerRevision(record), "requestHash": hash, "status": "sent", "desired": Record{"port": 24001 + i}}); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err = m.CancelPendingCreates(ctx, "clash", requests, func(string, string, int, Record) error { t.Fatal("remote mutation with canceled context"); return nil }); err == nil {
		t.Fatal("offline first path reported complete")
	}
	reopened, err := Open(root)
	if err != nil {
		t.Fatal(err)
	}
	for i, key := range keys {
		entry, err := reopened.loadCreate(key)
		if err != nil || (entry["cancelRequested"] != true && entry["status"] != "canceled") {
			t.Fatal("later path not durably fenced", i, entry, err)
		}
		if err = reopened.reserveCoreCreate(server, key, "", "delayed-intent"); err == nil {
			t.Fatal("late local reservation accepted", i)
		}
	}
}

func TestBatchCancelValidatesAllRequestIDsBeforeSavingIntent(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("f", 32)
	if _, err = m.CancelPendingCreates(context.Background(), "clash", []string{request, "invalid"}, nil); err == nil {
		t.Fatal("invalid batch accepted")
	}
	key, _, _ := createRequestIdentity("clash", Record{"operationId": request})
	entry, err := m.loadCreate(key)
	if err != nil || entry != nil {
		t.Fatal("invalid batch partially persisted", entry, err)
	}
}

func TestBatchCancellationIsAtomicOnJournalCapacityOrScopeFailure(t *testing.T) {
	for _, scenario := range []string{"capacity", "scope"} {
		t.Run(scenario, func(t *testing.T) {
			m, err := Open(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			journal := Record{}
			first := strings.Repeat("a", 64)
			last := strings.Repeat("b", 64)
			if scenario == "capacity" {
				for i := 0; i < 4095; i++ {
					journal[fmt.Sprintf("%064x", i)] = Record{"scope": "clash", "status": "canceled"}
				}
			} else {
				journal[last] = Record{"scope": "different-profile", "status": "canceled"}
			}
			before, _ := json.Marshal(journal)
			file := filepath.Join(m.root, "inbound-creates.json")
			if err = os.WriteFile(file, before, 0600); err != nil {
				t.Fatal(err)
			}
			if err = m.fenceCreateBatch("clash", []string{first, last}); err == nil {
				t.Fatal("invalid batch accepted")
			}
			after, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed batch partially fenced earlier path", err)
			}
		})
	}
}

func TestBatchCancellationDuplicateRequestsAreIdempotent(t *testing.T) {
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	request := strings.Repeat("a", 32)
	for i := 0; i < 2; i++ {
		if _, err = m.CancelPendingCreates(context.Background(), "clash", []string{request, request}, nil); err != nil {
			t.Fatal(err)
		}
	}
	journal, err := m.createJournal()
	if err != nil || len(journal) != 1 {
		t.Fatal("duplicate cancellation created extra entries", journal, err)
	}
}

func TestBatchCancelRacesWithPanelReservationWithoutLosingFence(t *testing.T) {
	for i := 0; i < 20; i++ {
		m, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		key, hash, _ := createRequestIdentity("clash", Record{"operationId": strings.Repeat("c", 32)})
		start := make(chan struct{})
		var wg sync.WaitGroup
		wg.Add(2)
		var cancelErr error
		go func() { defer wg.Done(); <-start; cancelErr = m.fenceCreateBatch("clash", []string{key}) }()
		go func() {
			defer wg.Done()
			<-start
			_ = m.persistCreate(key, Record{"scope": "clash", "serverId": "server", "revision": "revision", "requestHash": hash, "status": "prepared", "desired": Record{"port": 24001}})
		}()
		close(start)
		wg.Wait()
		if cancelErr != nil {
			t.Fatal(cancelErr)
		}
		entry, err := m.loadCreate(key)
		if err != nil || entry == nil || (entry["status"] != "canceled" && entry["cancelRequested"] != true) {
			t.Fatal("concurrent reservation lost cancellation", entry, err)
		}
	}
}
