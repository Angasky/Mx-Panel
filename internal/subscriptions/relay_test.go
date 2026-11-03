package subscriptions

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type relayBackend struct {
	*templateBackend
	failRoute bool
}

func (b *relayBackend) CreateRelay(ctx context.Context, server, profile string, payload Record) (Record, error) {
	result, err := b.templateBackend.CreateInbound(ctx, server, profile, payload)
	if err != nil {
		return nil, err
	}
	if b.failRoute {
		return nil, errors.New("route not confirmed")
	}
	return result, nil
}
func TestRelayDoesNotGrantUserBeforeRouteConfirmation(t *testing.T) {
	c, base, _ := controllerFixture(t)
	backend := &relayBackend{templateBackend: &templateBackend{fakeBackend: base, created: map[string]int{}}, failRoute: true}
	c.Backend = backend
	payload := Record{"operationId": strings.Repeat("a", 32)}
	if _, err := c.CreateRelay(context.Background(), "clash", "s", payload); err == nil || base.adds != 0 {
		t.Fatal("granted user before routing")
	}
	backend.failRoute = false
	result, err := c.CreateRelay(context.Background(), "clash", "s", payload)
	if err != nil || result["bound"] != true || backend.creates != 1 || base.adds != 1 {
		t.Fatal(result, err)
	}
	if _, err = c.CreateRelay(context.Background(), "clash", "s", payload); err != nil || backend.creates != 1 || base.adds != 1 {
		t.Fatal("retry duplicated relay/user", err)
	}
}
