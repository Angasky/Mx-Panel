package releaseupdate

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
)

func TestUninstallSharesDurableQueueWithUpdates(t *testing.T) {
	calls := 0
	m := &Manager{path: filepath.Join(t.TempDir(), "status.json"), launch: func(ctx context.Context, job Job) error {
		calls++
		if ctx.Err() != nil || job.Operation != "uninstall" {
			t.Fatal("invalid uninstall launch")
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	job, err := m.StartUninstall(ctx, "v1.0.0")
	if err != nil || calls != 1 {
		t.Fatal(job, err)
	}
	reopened := &Manager{path: m.path}
	if _, err := reopened.Start(context.Background(), "v1.0.0", "v2.0.0"); !errors.Is(err, ErrBusy) {
		t.Fatal("update raced removal", err)
	}
	if _, err := reopened.StartUninstall(context.Background(), "v1.0.0"); !errors.Is(err, ErrBusy) {
		t.Fatal("duplicate removal accepted", err)
	}
	if _, err := reopened.claimUninstall("v2.0.0", job.ID); err == nil {
		t.Fatal("changed version accepted")
	}
	if _, err := reopened.claimUninstall("v1.0.0", "wrong"); err == nil {
		t.Fatal("wrong job accepted")
	}
	if _, err := reopened.claim("v0.9.0", "v1.0.0", job.ID); err == nil {
		t.Fatal("removal claimed as update")
	}
	claimed, err := reopened.claimUninstall("v1.0.0", job.ID)
	if err != nil || claimed.Stage != "uninstall" {
		t.Fatal(err)
	}
	if _, err := reopened.claimUninstall("v1.0.0", job.ID); err == nil {
		t.Fatal("job claimed twice")
	}
}
func TestUpdateCannotBeClaimedAsUninstall(t *testing.T) {
	m := &Manager{path: filepath.Join(t.TempDir(), "status.json"), launch: func(context.Context, Job) error { return nil }}
	job, err := m.Start(context.Background(), "v1.0.0", "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.claimUninstall("v2.0.0", job.ID); err == nil {
		t.Fatal("update claimed as removal")
	}
	var absent *Manager
	if _, err := absent.StartUninstall(context.Background(), "v1.0.0"); err == nil {
		t.Fatal("nil installation accepted")
	}
}
func TestPurgeChoicePersistsBeforeWorkerLaunch(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	m := &Manager{path: path, launch: func(_ context.Context, job Job) error {
		reopened := &Manager{path: path}
		saved, err := reopened.Status()
		if err != nil || !saved.PurgeData || !job.PurgeData {
			t.Fatal("purge choice not durable", err)
		}
		return nil
	}}
	job, err := m.StartUninstallWithData(context.Background(), "v1.0.0", true)
	if err != nil {
		t.Fatal(err)
	}
	reopened := &Manager{path: path}
	claimed, err := reopened.claimUninstall("v1.0.0", job.ID)
	if err != nil || !claimed.PurgeData {
		t.Fatal("worker lost purge choice", err)
	}
}
