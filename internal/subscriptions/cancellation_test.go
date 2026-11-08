package subscriptions

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestOperationLockCancellationDoesNotAcquireOrLeak(t *testing.T) {
	c, _, _ := controllerFixture(t)
	for _, server := range []bool{false, true} {
		canceled, cancel := context.WithCancel(context.Background())
		cancel()
		for i := 0; i < 100; i++ {
			if release, err := c.operationLock(canceled, "fixture", server); !errors.Is(err, context.Canceled) {
				if release != nil {
					release()
				}
				t.Fatal("pre-canceled operation acquired lock", err)
			}
		}
		release, err := c.operationLock(context.Background(), "fixture", server)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		result := make(chan error, 1)
		go func() {
			unlock, err := c.operationLock(ctx, "fixture", server)
			if unlock != nil {
				unlock()
			}
			result <- err
		}()
		cancel()
		select {
		case err := <-result:
			if !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
		case <-time.After(time.Second):
			t.Fatal("blocked operation ignored cancellation")
		}
		release()
		unlock, err := c.operationLock(context.Background(), "fixture", server)
		if err != nil {
			t.Fatal("lock leaked", err)
		}
		unlock()
	}
}
