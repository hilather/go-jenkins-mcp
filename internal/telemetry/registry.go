package telemetry

import (
	"context"
	"sync"
)

// Registry holds the process logger and metrics for local observability.
// Future doctor/status (OPS-001) and OTLP export residual consume Snapshot.
type Registry struct {
	Logger  *Logger
	Metrics *Metrics
}

// NewRegistry builds a default stderr logger + empty metrics.
func NewRegistry() *Registry {
	return &Registry{
		Logger:  DefaultLogger(),
		Metrics: NewMetrics(),
	}
}

// Snapshot returns metrics only (logger has no snapshot state).
func (r *Registry) Snapshot() Snapshot {
	if r == nil || r.Metrics == nil {
		return Snapshot{Counters: map[string]int64{}, Gauges: map[string]int64{}}
	}
	return r.Metrics.Snapshot()
}

// Inc is a nil-safe metrics increment.
func (r *Registry) Inc(name string, delta int64) {
	if r == nil || r.Metrics == nil {
		return
	}
	r.Metrics.Inc(name, delta)
}

// Info logs via the registry logger when present.
func (r *Registry) Info(msg string, kvs ...string) {
	if r == nil || r.Logger == nil {
		return
	}
	r.Logger.Info(msg, kvs...)
}

type regCtxKey struct{}

// WithRegistry stores r on the context.
func WithRegistry(ctx context.Context, r *Registry) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if r == nil {
		return ctx
	}
	return context.WithValue(ctx, regCtxKey{}, r)
}

// RegistryFromContext returns the Registry from ctx, or nil.
func RegistryFromContext(ctx context.Context) *Registry {
	if ctx == nil {
		return nil
	}
	r, _ := ctx.Value(regCtxKey{}).(*Registry)
	return r
}

// Global optional registry for cmd wiring when context is not available.
// Prefer context values; this is a fallback for early init only.
var (
	globalMu sync.RWMutex
	global   *Registry
)

// SetGlobal installs an optional process-wide registry (serve startup).
func SetGlobal(r *Registry) {
	globalMu.Lock()
	global = r
	globalMu.Unlock()
}

// Global returns the process-wide registry, or nil.
func Global() *Registry {
	globalMu.RLock()
	defer globalMu.RUnlock()
	return global
}
