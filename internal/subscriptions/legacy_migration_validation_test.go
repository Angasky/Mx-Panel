package subscriptions

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/Angasky/dingzhi-ban/internal/config"
)

type migrationRegistryBackend struct {
	*fakeBackend
	fields      Record
	inventories int
}

func (b *migrationRegistryBackend) Record(id string) (Record, error) {
	record, err := b.fakeBackend.Record(id)
	for key, value := range b.fields {
		record[key] = value
	}
	return record, err
}
func (b *migrationRegistryBackend) Inbounds(ctx context.Context, id string) (Record, error) {
	b.inventories++
	return b.fakeBackend.Inbounds(ctx, id)
}

func TestLegacyMigrationRejectsMalformedRegistriesBeforeRemoteRead(t *testing.T) {
	cases := []struct {
		name         string
		fields       Record
		bandwidth    any
		setBandwidth bool
		message      string
	}{
		{"bandwidth-registry-string", Record{"bandwidths": "{}"}, nil, false, "bandwidths"},
		{"bandwidth-registry-null", Record{"bandwidths": nil}, nil, false, "bandwidths"},
		{"bandwidth-registry-list", Record{"bandwidths": []any{}}, nil, false, "bandwidths"},
		{"binding-bandwidth-null", Record{}, nil, true, "bandwidth"},
		{"binding-bandwidth-string", Record{}, "{}", true, "bandwidth"},
		{"meter-registry-null", Record{"meters": nil}, nil, false, "meters"},
		{"meter-registry-list", Record{"meters": []any{}}, nil, false, "meters"},
		{"meter-port-mismatch", Record{"meters": Record{"1": 24002}}, nil, false, "端口不一致"},
		{"meter-target-null", Record{"meters": Record{"1": nil}}, nil, false, "端口不一致"},
		{"meter-target-bool", Record{"meters": Record{"1": true}}, nil, false, "端口不一致"},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			c, base, _ := controllerFixture(t)
			binding := Record{"serverId": "s", "inboundId": 1, "port": 24001, "status": "active", "counterSource": "inbound", "identityHash": "legacy"}
			if test.setBandwidth {
				binding["bandwidth"] = test.bandwidth
			}
			if err := c.Repository.UpdateState("clash", func(p Record) error {
				p["remoteNodes"] = []any{binding}
				p["traffic"] = Record{"upload": 41}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
			backend := &migrationRegistryBackend{fakeBackend: base, fields: test.fields}
			c.Backend = backend
			before, err := c.Repository.State("clash")
			if err != nil {
				t.Fatal(err)
			}
			token := config.BindingToken("clash", stateBinding(t, c))
			_, err = c.MigrateLegacyBinding(context.Background(), "clash", 0, token, true)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatal("invalid registry not rejected", err)
			}
			after, _ := c.Repository.State("clash")
			if !reflect.DeepEqual(before, after) || backend.inventories != 0 || len(base.ops) != 0 {
				t.Fatal("invalid registry changed local/remote state")
			}
		})
	}
}
