package adapter

import (
	"context"
	"sync"
	"time"
)

// Capability is a coarse, non-secret capability label an adapter may declare.
// Tool contracts and policy use these to reason about cross-system movement.
type Capability string

const (
	// CapLifecycle marks adapters that only manage their own lifecycle/health.
	CapLifecycle Capability = "lifecycle"
	// CapClock is the test/example wall-clock capability (not a production integration).
	CapClock Capability = "clock"
	// CapTelemetry marks OpenTelemetry correlation lite (INT-002; no OTLP export).
	CapTelemetry Capability = "telemetry"
	// CapOtelExport marks the metadata-only OTLP export framework stub (INT-002).
	// Real OTLP/OTLP-HTTP protobuf collector clients remain residual.
	CapOtelExport Capability = "otel_export"
	// CapExternalLogs is reserved for external log backends (INT-003).
	CapExternalLogs Capability = "external_logs"
	// CapWorkItem is reserved for work-item correlation (INT-004).
	CapWorkItem Capability = "work_item"
)

// HealthStatus is a coarse health enum for adapters.
type HealthStatus string

const (
	// HealthUnknown means the adapter has not reported yet (or never started).
	HealthUnknown HealthStatus = "unknown"
	// HealthStarting means Start is in progress.
	HealthStarting HealthStatus = "starting"
	// HealthHealthy means the adapter is running and usable.
	HealthHealthy HealthStatus = "healthy"
	// HealthUnhealthy means the adapter failed, panicked, or reported bad health.
	HealthUnhealthy HealthStatus = "unhealthy"
	// HealthStopped means Stop completed (or never started and is idle).
	HealthStopped HealthStatus = "stopped"
	// HealthDisabled means the adapter is known but not enabled in this process.
	HealthDisabled HealthStatus = "disabled"
)

// Health is a point-in-time health report (no secrets).
type Health struct {
	Status  HealthStatus `json:"status"`
	Message string       `json:"message,omitempty"`
	// CheckedAt is wall time of the report (UTC).
	CheckedAt time.Time `json:"checked_at,omitempty"`
}

// Adapter is the lifecycle surface every integration must implement.
// Implementations must not retain Jenkins credentials or raw Jenkins clients
// unless a future narrow interface is explicitly injected by the host.
type Adapter interface {
	// ID returns a stable, lowercase adapter identifier (e.g. "clock").
	ID() string
	// Capabilities returns the capability labels this adapter exposes.
	Capabilities() []Capability
	// Start prepares the adapter. May be called at most once per process lifetime
	// unless Stop has completed and the host re-enables (MVP: single Start).
	Start(ctx context.Context) error
	// Stop tears down the adapter. Safe to call when not started (no-op / nil error).
	Stop(ctx context.Context) error
	// Health reports current health. Must not panic; registry also recovers.
	Health(ctx context.Context) Health
}

// Host is the narrow surface the core process may pass into adapters.
// It intentionally omits Jenkins clients, keyrings, and token material.
// Future integrations add optional interfaces here without granting Jenkins access.
type Host struct {
	// Now is an optional clock for tests; when nil, time.Now is used.
	Now func() time.Time
	// Logger is an optional non-secret log sink (printf-style). Never pass secrets.
	Logger func(format string, args ...any)
}

// now returns Host.Now or time.Now.UTC.
func (h Host) now() time.Time {
	if h.Now != nil {
		return h.Now().UTC()
	}
	return time.Now().UTC()
}

// logf logs if Logger is set.
func (h Host) logf(format string, args ...any) {
	if h.Logger != nil {
		h.Logger(format, args...)
	}
}

// Factory constructs an Adapter given a Host. Factories must not capture secrets.
type Factory func(host Host) (Adapter, error)

// Entry is a registered running (or failed) adapter instance plus metadata.
type Entry struct {
	ID           string
	Capabilities []Capability
	Adapter      Adapter
	// RateLimit is optional; nil means unlimited (still subject to host budgets later).
	RateLimit *TokenBucket

	mu     sync.Mutex
	health Health
	// panicked is set when a recovered panic made the adapter unhealthy.
	panicked bool
	started  bool
	stopped  bool
}

// snapshotHealth returns a copy of the last health under lock.
func (e *Entry) snapshotHealth() Health {
	e.mu.Lock()
	defer e.mu.Unlock()
	h := e.health
	return h
}

// setHealth updates stored health.
func (e *Entry) setHealth(h Health) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.health = h
}

// markPanic records a panic and forces unhealthy.
func (e *Entry) markPanic(msg string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.panicked = true
	e.health = Health{
		Status:    HealthUnhealthy,
		Message:   msg,
		CheckedAt: time.Now().UTC(),
	}
}
