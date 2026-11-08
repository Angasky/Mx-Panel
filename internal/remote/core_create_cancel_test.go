package remote

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestCoreCancellationFenceBlocksLateWritersAndActiveLock(t *testing.T) {
	root := t.TempDir()
	key := strings.Repeat("a", 64)
	lock := filepath.Join(root, "writer.lock")
	rewrite := func(script string) string {
		script = strings.ReplaceAll(script, "/var/lock/mxioc-xui-install.lock", lock)
		return strings.ReplaceAll(script, "/var/lib/mxioc/create-canceled", filepath.Join(root, "canceled"))
	}
	held, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err = syscall.Flock(int(held.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err = exec.Command("bash", "-c", rewrite(coreCreateFenceScript(key))).Run(); err == nil {
		t.Fatal("fenced while original writer still holds lock")
	}
	_ = syscall.Flock(int(held.Fd()), syscall.LOCK_UN)
	if output, err := exec.Command("bash", "-c", rewrite(coreCreateFenceScript(key))).CombinedOutput(); err != nil {
		t.Fatal(string(output), err)
	}
	script, err := coreWriteScript("xray", []byte(`{"inbounds":[]}`), Record{"inbounds": []any{}}, "", "", key)
	if err != nil {
		t.Fatal(err)
	}
	// Only the lock and fence prelude is executed, with temporary paths. No
	// systemctl or real configuration operation can be reached in this test.
	start := strings.Index(script, "exec 9>")
	end := strings.Index(script, "test -f")
	prelude := rewrite("set -Eeuo pipefail\n"+script[start:end]) + "printf unexpected-write"
	output, err := exec.Command("bash", "-c", prelude).CombinedOutput()
	if err == nil || len(output) != 0 {
		t.Fatal("late writer passed cancellation", string(output), err)
	}
}
func TestCorePendingCreateCancellationAndInterruptedCleanup(t *testing.T) {
	for _, kind := range []string{"xray", "sing-box"} {
		for _, applied := range []bool{false, true} {
			t.Run(kind+"/"+value(applied), func(t *testing.T) {
				root := t.TempDir()
				m, err := Open(root)
				if err != nil {
					t.Fatal(err)
				}
				payload := serverPayload()
				payload["installType"] = kind
				delete(payload, "panelAddress")
				public, err := m.Save(payload)
				if err != nil {
					t.Fatal(err)
				}
				server := value(public["id"])
				request := strings.Repeat("c", 32)
				key, hash, _ := createRequestIdentity("clash", Record{"operationId": request})
				row, err := buildInboundTemplate(Record{"template": "vmess-tcp", "port": 24001, "remark": "cancel"}, "")
				if err != nil {
					t.Fatal(err)
				}
				row["id"], row["tag"], row["goCreateKey"], row["goCreateHash"] = 1, "mxioc-inbound-1", key, hash
				native, err := legacyNativeInbound(kind, row)
				if err != nil {
					t.Fatal(err)
				}
				before := []byte(`{"inbounds":[],"outbounds":[]}`)
				after, _ := json.Marshal(Record{"inbounds": []any{native}, "outbounds": []any{}})
				intent := Record{"key": key, "operation": coreInboundCreate, "before": coreConfigHash(before), "after": coreConfigHash(after), "row": row, "cancelFence": true}
				token, _ := m.SealUser(intent)
				if err = m.updateCoreUserState(server, "", "", "", token); err != nil {
					t.Fatal(err)
				}
				target, err := m.reserveCoreCancel("clash", key)
				if err != nil || target != server {
					t.Fatal(target, err)
				}
				raw := before
				if applied {
					raw = after
				}
				writes := 0
				interrupt := applied
				run := func(ctx context.Context, command string, limit int) (string, error) {
					if strings.Contains(command, "MXIOC_CREATE_FENCED") {
						return "MXIOC_CREATE_FENCED", nil
					}
					if strings.HasPrefix(command, "base64 < ") {
						return base64.StdEncoding.EncodeToString(raw), nil
					}
					if strings.Contains(command, "MXIOC_CORE_APPLIED") {
						start := strings.Index(command, "printf '%s' '")
						if start < 0 {
							t.Fatal("missing candidate")
						}
						encoded := strings.SplitN(command[start+len("printf '%s' '"):], "'", 2)[0]
						raw, err = base64.StdEncoding.DecodeString(encoded)
						if err != nil {
							t.Fatal(err)
						}
						writes++
						if interrupt {
							interrupt = false
							return "", errors.New("disconnect after cleanup")
						}
						return "MXIOC_CORE_APPLIED", nil
					}
					t.Fatal("unexpected runner operation")
					return "", nil
				}
				guard := func(request, server string, id int, row Record) error {
					if id != 1 {
						return errors.New("wrong id")
					}
					return nil
				}
				record, _ := m.Record(server)
				err = m.cancelCoreCreate(context.Background(), server, kind, key, request, record, run, guard)
				if applied {
					if err == nil {
						t.Fatal("expected interrupted cleanup")
					}
					m, err = Open(root)
					if err != nil {
						t.Fatal(err)
					}
					record, _ = m.Record(server)
					err = m.cancelCoreCreate(context.Background(), server, kind, key, request, record, run, guard)
				}
				if err != nil {
					t.Fatal(err)
				}
				record, _ = m.Record(server)
				if value(record["coreUserPending"]) != "" {
					t.Fatal("cleanup intent retained")
				}
				// Covers a crash after state save but before the create tombstone is finalized.
				if err = m.cancelCoreCreate(context.Background(), server, kind, key, request, record, run, guard); err != nil {
					t.Fatal("finalization retry failed", err)
				}
				if err = m.finishCreateCancel("clash", key); err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(raw), "mxioc-inbound-1") || writes > 1 {
					t.Fatal("late inbound retained or cleanup replayed")
				}
			})
		}
	}
}

func TestCancellationRejectsMalformedLists(t *testing.T) {
	for _, raw := range []any{nil, Record{}, "bad", []any{nil}, []any{Record{"tag": "owned"}, "corrupt"}, []any{Record(nil)}} {
		if _, err := cancellationRecords(raw); err == nil {
			t.Fatal("malformed record would be silently dropped", raw)
		}
	}
}
