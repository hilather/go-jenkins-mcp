package fleetmcp

import (
	"context"
)

// Service is the coordinator for fleet_* MCP tools.
type Service struct {
	Cfg   Config
	Local *LocalProvider
	Peers PeerFetcher
}

// New builds a Service. Callers must pass Enabled Config.
func New(cfg Config, local *LocalProvider, peers PeerFetcher) *Service {
	if local == nil {
		local = &LocalProvider{}
	}
	return &Service{Cfg: cfg, Local: local, Peers: peers}
}

// Enabled reports whether fleet tools may register.
func (s *Service) Enabled() bool {
	return s != nil && s.Cfg.Enabled && s.Cfg.TrustConfigured && s.Cfg.Roster != nil
}

// ListMembers returns roster membership (no fan-out network required for static roster).
// Optionally includes reachability if Peers is set (uses CollectionMembers peer path).
func (s *Service) ListMembers(ctx context.Context) AggregateEnvelope {
	if !s.Enabled() {
		return BuildEnvelope(s.Cfg, CollectionMembers, nil, nil)
	}
	// Use fan-out member endpoint for reachability probe.
	return FanOut(ctx, s.Cfg, s.Local, s.Peers, CollectionMembers)
}

// Collect runs a fleet-wide read collection.
func (s *Service) Collect(ctx context.Context, collection Collection) AggregateEnvelope {
	if !s.Enabled() {
		return BuildEnvelope(s.Cfg, collection, nil, nil)
	}
	return FanOut(ctx, s.Cfg, s.Local, s.Peers, collection)
}

// ToolCatalog lists fleet_* tool names (for registration tests).
func ToolCatalog() []string {
	return []string{
		"fleet_list_members",
		"fleet_health",
		"fleet_version",
		"fleet_metrics",
		"fleet_residual_status",
		"fleet_doctor",
		"fleet_cache_status",
	}
}
