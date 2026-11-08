package subscriptions

import (
	"context"
	"errors"
	"testing"
	"time"
)

type shutdownBackend struct {
	*fakeBackend
	entered, release chan struct{}
}

func (b *shutdownBackend) Inbounds(ctx context.Context, id string) (Record, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-b.release
	return nil, ctx.Err()
}

func TestWaitStoppedJoinsInFlightSweepAndAllowsRestart(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	blocker := &shutdownBackend{fakeBackend: b, entered: make(chan struct{}, 1), release: make(chan struct{})}
	c.Backend = blocker
	c.started.Store(false)
	if err := c.WaitStopped(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	released := false
	defer func() {
		cancel()
		if !released {
			close(blocker.release)
		}
		wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := c.WaitStopped(wait); err != nil {
			t.Error(err)
		}
	}()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case <-blocker.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("worker did not enter backend")
	}
	cancel()
	short, stop := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := c.WaitStopped(short)
	stop()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("wait returned before in-flight work finished", err)
	}
	if err := c.Start(context.Background()); err == nil {
		t.Fatal("restarted before prior worker stopped")
	}
	close(blocker.release)
	released = true
	wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	if err := c.WaitStopped(wait); err != nil {
		t.Fatal(err)
	}
	c.Backend = b
	next, stopNext := context.WithCancel(context.Background())
	defer stopNext()
	if err := c.Start(next); err != nil {
		t.Fatal("restart failed", err)
	}
	stopNext()
	if err := c.WaitStopped(wait); err != nil {
		t.Fatal(err)
	}
}
