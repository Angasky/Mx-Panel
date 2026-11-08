package subscriptions

import (
	"context"
	"testing"
	"time"
)

type observedPolicyBackend struct {
	*fakeBackend
	sampled chan struct{}
}

func (b *observedPolicyBackend) SubscriptionUser(ctx context.Context, server string, binding Record, operation string, user Record) (Record, error) {
	result, err := b.fakeBackend.SubscriptionUser(ctx, server, binding, operation, user)
	if operation == "read" {
		select {
		case b.sampled <- struct{}{}:
		default:
		}
	}
	return result, err
}

func TestQuotaSaveWakesBackgroundEnforcementWithoutWaitingForInterval(t *testing.T) {
	c, b, _ := controllerFixture(t)
	if _, err := c.Batch(context.Background(), "clash", "s", []int{1}); err != nil {
		t.Fatal(err)
	}
	observer := &observedPolicyBackend{fakeBackend: b, sampled: make(chan struct{}, 8)}
	c.Backend = observer
	c.started.Store(false)
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		cancel()
		wait, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		if err := c.WaitStopped(wait); err != nil {
			t.Error("background worker did not stop", err)
		}
	}()
	if err := c.Start(ctx); err != nil {
		t.Fatal(err)
	}
	waitSample := func() {
		t.Helper()
		select {
		case <-observer.sampled:
		case <-time.After(3 * time.Second):
			t.Fatal("quota update did not wake worker before the 15-second interval")
		}
	}
	waitSample()
	if _, err := c.EditTraffic(ctx, "clash", Record{"preserveUsage": true, "total": 10000}); err != nil {
		t.Fatal(err)
	}
	waitSample()
}
