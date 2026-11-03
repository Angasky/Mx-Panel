package subscriptions

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

type inboundBackend struct {
	*fakeBackend
	writes    int
	uncertain bool
}

func (b *inboundBackend) UpdateInbound(ctx context.Context, server string, id int, payload Record, expected string, guard func(Record, Record) error) (Record, error) {
	old := clone(b.rows[id-1])
	next := clone(old)
	for k, v := range payload {
		next[k] = v
	}
	if err := guard(old, next); err != nil {
		return nil, err
	}
	b.writes++
	b.rows[id-1] = next
	return Record{"updated": true}, nil
}
func (b *inboundBackend) DeleteInbound(ctx context.Context, server string, id int, expected string, guard func(Record) error) (Record, error) {
	if err := guard(clone(b.rows[id-1])); err != nil {
		return nil, err
	}
	b.writes++
	if b.uncertain {
		return nil, errors.New("write result uncertain")
	}
	b.rows = append(b.rows[:id-1], b.rows[id:]...)
	return Record{"deleted": true}, nil
}

func TestInboundWriterGuardsAndCleansImportedNodes(t *testing.T) {
	c, base, _ := controllerFixture(t)
	writer := &inboundBackend{fakeBackend: base}
	c.Backend = writer
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1, 2}); err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("a", 64)
	if _, err := c.WriteInbound(context.Background(), "s", 1, Record{"settings": Record{"clients": []any{}}}, token, false); err == nil || writer.writes != 0 {
		t.Fatal("bound client removed", err)
	}
	if _, err := c.WriteInbound(context.Background(), "s", 1, Record{"enable": false}, token, false); err != nil {
		t.Fatal(err)
	}
	writer.uncertain = true
	if _, err := c.WriteInbound(context.Background(), "s", 1, nil, token, true); err == nil {
		t.Fatal("uncertain delete accepted")
	}
	snap, _ := c.Repository.Snapshot("clash")
	if len(snap["nodes"].([]any)) != 2 {
		t.Fatal("ambiguous deletion pruned nodes")
	}
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err == nil {
		t.Fatal("pending deletion accepted import")
	}
	writer.uncertain = false
	result, err := c.WriteInbound(context.Background(), "s", 1, nil, token, true)
	if err != nil || result["removedLocalNodes"] != 1 {
		t.Fatal(result, err)
	}
	snap, _ = c.Repository.Snapshot("clash")
	if len(snap["nodes"].([]any)) != 1 {
		t.Fatal("wrong nodes removed")
	}
}

func TestInboundServerLockWaitIsCancelableBeforeRemoteWrite(t *testing.T) {
	c, base, _ := controllerFixture(t)
	writer := &inboundBackend{fakeBackend: base}
	c.Backend = writer
	release, err := c.lockServer(context.Background(), "s")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	_, err = c.WriteInbound(ctx, "s", 1, nil, strings.Repeat("a", 64), true)
	if !errors.Is(err, context.DeadlineExceeded) || writer.writes != 0 {
		t.Fatal("lock ignored cancellation", err)
	}
}
