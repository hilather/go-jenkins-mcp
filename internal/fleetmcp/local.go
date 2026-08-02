package fleetmcp

import (
	"context"
	"runtime"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/diagnostics"
	"github.com/hilather/go-jenkins-mcp/internal/store"
	"github.com/hilather/go-jenkins-mcp/internal/telemetry"
)

// LocalProvider supplies secret-free local snapshots for the coordinator.
// Injected for tests; production wires process metrics/version/doctor/cache.
type LocalProvider struct {
	Version   string
	Commit    string
	BuildTime string
	Metrics   *telemetry.Metrics
	Getenv    func(string) string
	// ProfileID optional for doctor/cache.
	ProfileID string
	// DataDir optional profile data dir for cache status.
	DataDir string
	// DoctorOffline optional; when nil, doctor residual notes offline-unavailable.
	DoctorOffline func(ctx context.Context) (map[string]any, error)
}

func (p *LocalProvider) getenv() func(string) string {
	if p != nil && p.Getenv != nil {
		return p.Getenv
	}
	return func(string) string { return "" }
}

// SnapshotLocal returns the local payload for a collection (always ok unless internal error).
func (p *LocalProvider) SnapshotLocal(ctx context.Context, collection Collection) (any, error) {
	switch collection {
	case CollectionHealth:
		return p.health(), nil
	case CollectionVersion:
		return p.version(), nil
	case CollectionMetrics:
		return p.metrics(), nil
	case CollectionResidual:
		return diagnostics.BuildGatewayResidualStatus(p.getenv()), nil
	case CollectionDoctor:
		return p.doctor(ctx)
	case CollectionCache:
		return p.cache(ctx)
	case CollectionMembers:
		return map[string]any{
			"self": true,
			"note": "use fleet_list_members for roster; local only",
		}, nil
	default:
		return map[string]any{"residual": "unknown collection"}, nil
	}
}

func (p *LocalProvider) health() map[string]any {
	v, c := "", ""
	if p != nil {
		v, c = p.Version, p.Commit
	}
	return map[string]any{
		"status":           "ok",
		"version":          v,
		"commit":           c,
		"gateway_ready":    false,
		"ha_multi_replica": false,
		"residual":         "fleet peer/local health; not multi-pod HA",
	}
}

func (p *LocalProvider) version() map[string]any {
	v, c, bt := "", "", ""
	if p != nil {
		v, c, bt = p.Version, p.Commit, p.BuildTime
	}
	return map[string]any{
		"version":    v,
		"commit":     c,
		"build_time": bt,
		"go_version": runtime.Version(),
		"os":         runtime.GOOS,
		"arch":       runtime.GOARCH,
	}
}

func (p *LocalProvider) metrics() map[string]any {
	var m *telemetry.Metrics
	if p != nil {
		m = p.Metrics
	}
	if m == nil {
		if reg := telemetry.Global(); reg != nil {
			m = reg.Metrics
		}
	}
	if m == nil {
		return map[string]any{
			"available": false,
			"counters":  map[string]int64{},
			"gauges":    map[string]int64{},
			"residual":  "process-local metrics empty",
		}
	}
	snap := m.Snapshot()
	if snap.Counters == nil {
		snap.Counters = map[string]int64{}
	}
	if snap.Gauges == nil {
		snap.Gauges = map[string]int64{}
	}
	return map[string]any{
		"available": true,
		"counters":  snap.Counters,
		"gauges":    snap.Gauges,
		"residual":  "process-local snapshot; multi-pod aggregation not applicable",
	}
}

func (p *LocalProvider) doctor(ctx context.Context) (any, error) {
	if p != nil && p.DoctorOffline != nil {
		return p.DoctorOffline(ctx)
	}
	return map[string]any{
		"available": false,
		"offline":   true,
		"residual":  "doctor snapshot not wired for this process",
	}, nil
}

func (p *LocalProvider) cache(ctx context.Context) (any, error) {
	_ = ctx
	dataDir := ""
	if p != nil {
		dataDir = strings.TrimSpace(p.DataDir)
	}
	if dataDir == "" {
		return map[string]any{
			"available": false,
			"residual":  "no profile data dir for cache status",
		}, nil
	}
	meta, err := store.Open(dataDir)
	if err != nil {
		return map[string]any{
			"available": false,
			"residual":  "cache store unavailable",
		}, nil
	}
	defer func() { _ = meta.Close() }()
	qcfg, err := store.ResolveQuotaConfigFromEnviron(
		p.getenv()(store.EnvCacheTotalQuotaBytes),
		p.getenv()(store.EnvCacheLowDiskBytes),
	)
	if err != nil {
		return map[string]any{
			"available": false,
			"residual":  "quota resolve failed",
		}, nil
	}
	qm, err := store.NewQuotaManager(meta, dataDir, qcfg)
	if err != nil {
		return map[string]any{
			"available": false,
			"residual":  "quota manager unavailable",
		}, nil
	}
	need, usage, err := qm.NeedsEviction(ctx)
	if err != nil {
		return map[string]any{
			"available": false,
			"residual":  "usage unavailable",
		}, nil
	}
	// Secret-free: bytes and flags only (no absolute paths).
	return map[string]any{
		"available":            true,
		"needs_eviction":       need,
		"total_physical_bytes": usage.TotalPhysicalBytes,
		"l1_physical_bytes":    usage.L1PhysicalBytes,
		"l2_physical_bytes":    usage.L2PhysicalBytes,
		"quota_bytes":          usage.QuotaBytes,
		"over_quota":           usage.OverQuota,
		"generations":          usage.Generations,
		"packs":                usage.Packs,
		"residual":             "fleet cache status lite; paths omitted",
	}, nil
}
