package remote

import (
	"context"
	"github.com/Angasky/dingzhi-ban/internal/coreapi"
	"sync"
)

// CoreRPCPlan contains data, never a peer supplied shell command. The Agent
// builds the same validated write/rollback scripts locally from this plan.
type CoreRPCPlan = coreapi.Plan
type CoreRPC func(context.Context, CoreRPCPlan) (string, error)
type CoreRPCResolver func(string, Record) CoreRPC
type coreRPCKey struct{}
type coreRPCPreferredKey struct{}
type coreRPCChoices struct {
	mu      sync.Mutex
	choices map[string]CoreRPC
}

func chosenCoreRPC(ctx context.Context, id string, record Record, resolver CoreRPCResolver) CoreRPC {
	choices, ok := ctx.Value(coreRPCPreferredKey{}).(*coreRPCChoices)
	if !ok || resolver == nil {
		return nil
	}
	choices.mu.Lock()
	defer choices.mu.Unlock()
	if rpc, exists := choices.choices[id]; exists {
		return rpc
	}
	rpc := resolver(id, record)
	choices.choices[id] = rpc
	return rpc
}

func PreferCoreAPI(ctx context.Context) context.Context {
	return context.WithValue(ctx, coreRPCPreferredKey{}, &coreRPCChoices{choices: map[string]CoreRPC{}})
}

func (m *Manager) SetCoreRPCResolver(resolve CoreRPCResolver) {
	m.mu.Lock()
	m.coreRPCResolver = resolve
	m.mu.Unlock()
}
func coreRPCExec(ctx context.Context, run coreRunner, plan CoreRPCPlan, script string, limit int) (string, error) {
	if rpc, ok := ctx.Value(coreRPCKey{}).(CoreRPC); ok {
		return rpc(ctx, plan)
	}
	return run(ctx, script, limit)
}

const xrayStatsReady = coreapi.XrayStatsReady

func ExecuteCoreRPC(ctx context.Context, p CoreRPCPlan, run func(context.Context, string, int) (string, error)) (string, error) {
	return coreapi.Execute(ctx, p, run)
}
