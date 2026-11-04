package releaseupdate

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReleaseArchiveChecksChecksumAndRejectsUnexpectedEntries(t *testing.T) {
	build := func(extra string) []byte {
		t.Helper()
		var out bytes.Buffer
		gz := gzip.NewWriter(&out)
		tw := tar.NewWriter(gz)
		add := func(name, body string) {
			t.Helper()
			if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0600, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(body)); err != nil {
				t.Fatal(err)
			}
		}
		for name, body := range map[string]string{"mxioc": "fixture", "index.html": "<html>",
			"mxioc-go-release.service": "fixture", "VERSION": "v2.0.0\n", "ARCH": "amd64\n",
			"SHA256SUMS": "fixture", "install-go.sh": "untrusted installer"} {
			add(name, body)
		}
		if extra != "" {
			add(extra, "unexpected")
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		return out.Bytes()
	}
	pkg := build("")
	name := "mxioc-go-v2.0.0-linux-amd64.tar.gz"
	manifest := []byte(fmt.Sprintf("%x  %s\n", sha256.Sum256(pkg), name))
	if err := verifyArchive(manifest, pkg, name); err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{[]byte("tampered"), build("../escape")} {
		if err := verifyArchive(manifest, bad, name); err == nil {
			t.Fatal("checksum accepted a different archive")
		}
	}
	dir := t.TempDir()
	if err := extractRelease(pkg, dir, "v2.0.0", "amd64"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "install-go.sh")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("downloaded installer was written", err)
	}
	for _, name := range []string{"../escape", "mxioc"} {
		if err := extractRelease(build(name), t.TempDir(), "v2.0.0", "amd64"); err == nil {
			t.Fatal("accepted unexpected or duplicate file")
		}
	}
	if err := extractRelease(pkg, t.TempDir(), "v2.0.0", "arm64"); err == nil {
		t.Fatal("accepted an archive for a different architecture")
	}
}

func TestQueuedReleaseIsDurableAndOnlyClaimedOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "status.json")
	manager := &Manager{path: path, launch: func(ctx context.Context, job Job) error {
		if ctx.Err() != nil || job.ID == "" {
			t.Fatal("launch should survive the HTTP request closing")
		}
		return nil
	}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.Start(ctx, "v2.0.0", "v1.0.0"); err == nil {
		t.Fatal("downgrade accepted")
	}
	job, err := manager.Start(ctx, "v1.0.0", "v2.0.0")
	if err != nil {
		t.Fatal(err)
	}
	reopened := &Manager{path: path}
	if _, err := reopened.Start(ctx, "v1.0.0", "v2.0.0"); !errors.Is(err, ErrBusy) {
		t.Fatal("duplicate launch allowed", err)
	}
	if _, err := reopened.claim("v1.0.0", "v2.0.0", "different"); err == nil {
		t.Fatal("wrong job identifier accepted")
	}
	running, err := reopened.claim("v1.0.0", "v2.0.0", job.ID)
	if err != nil || running.Status != "running" {
		t.Fatal(running, err)
	}
	if _, err := reopened.claim("v1.0.0", "v2.0.0", job.ID); err == nil {
		t.Fatal("the same job was claimed twice")
	}
	running.Started = time.Now().Add(-13 * time.Minute).Unix()
	if err := manager.save(*running); err != nil {
		t.Fatal(err)
	}
	if status, err := reopened.Status(); err != nil || status.Status != "interrupted" {
		t.Fatal(status, err)
	}
}
