package adapter

import (
	"context"
	"sync"
	"time"
)

// Built-in test/example adapter IDs (not production external systems).
// otel-correlate is a lifecycle marker for INT-002 correlation lite (no OTLP).
// otel-export is the INT-002 metadata-only export framework stub (no OTLP protobuf).
// ext-logs / work-items are MVP stubs (INT-003 / INT-004); no real SaaS clients.
const (
	IDNoop          = "noop"
	IDClock         = "clock"
	IDOtelCorrelate = "otel-correlate"
	// IDOtelExport, IDExtLogs, and IDWorkItems are defined in otelexport.go /
	// extlogs.go / workitems.go.
)

// BuiltinIDs is the closed set of in-tree example/feature adapters.
var BuiltinIDs = []string{IDNoop, IDClock, IDOtelCorrelate, IDOtelExport, IDExtLogs, IDWorkItems}

// IsBuiltin reports whether id is a shipped test/example adapter.
func IsBuiltin(id string) bool {
	switch normalizeID(id) {
	case IDNoop, IDClock, IDOtelCorrelate, IDOtelExport, IDExtLogs, IDWorkItems:
		return true
	default:
		return false
	}
}

// DefaultCatalog returns factories for built-in adapters only.
// ext-logs / otel-export default to the noop backend (no network). Override the
// catalog entry with ExtLogsFactory / OtelExportFactory when backend flags are set.
func DefaultCatalog() map[string]Factory {
	return map[string]Factory{
		IDNoop:          NewNoop,
		IDClock:         NewClock,
		IDOtelCorrelate: NewOtelCorrelate,
		IDOtelExport:    NewOtelExportDefault,
		IDExtLogs:       NewExtLogsDefault,
		IDWorkItems:     NewWorkItems,
	}
}

// --- noop ---

// Noop is a no-op adapter used for framework tests and smoke enablement.
type Noop struct {
	host    Host
	mu      sync.Mutex
	started bool
	stopped bool
}

// NewNoop constructs a Noop adapter.
func NewNoop(host Host) (Adapter, error) {
	return &Noop{host: host}, nil
}

func (n *Noop) ID() string { return IDNoop }

func (n *Noop) Capabilities() []Capability { return []Capability{CapLifecycle} }

func (n *Noop) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	n.mu.Lock()
	n.started = true
	n.stopped = false
	n.mu.Unlock()
	n.host.logf("adapter noop: started")
	return nil
}

func (n *Noop) Stop(ctx context.Context) error {
	_ = ctx
	n.mu.Lock()
	n.stopped = true
	n.started = false
	n.mu.Unlock()
	n.host.logf("adapter noop: stopped")
	return nil
}

func (n *Noop) Health(ctx context.Context) Health {
	_ = ctx
	n.mu.Lock()
	defer n.mu.Unlock()
	switch {
	case n.stopped && !n.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: n.host.now()}
	case n.started:
		return Health{Status: HealthHealthy, Message: "ok", CheckedAt: n.host.now()}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: n.host.now()}
	}
}

// --- clock ---

// Clock is a test/example adapter that exposes wall time via Now().
// It is not a production external-system integration.
type Clock struct {
	host    Host
	mu      sync.Mutex
	started bool
	stopped bool
}

// NewClock constructs a Clock adapter.
func NewClock(host Host) (Adapter, error) {
	return &Clock{host: host}, nil
}

func (c *Clock) ID() string { return IDClock }

func (c *Clock) Capabilities() []Capability {
	return []Capability{CapLifecycle, CapClock}
}

func (c *Clock) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	c.started = true
	c.stopped = false
	c.mu.Unlock()
	c.host.logf("adapter clock: started")
	return nil
}

func (c *Clock) Stop(ctx context.Context) error {
	_ = ctx
	c.mu.Lock()
	c.stopped = true
	c.started = false
	c.mu.Unlock()
	c.host.logf("adapter clock: stopped")
	return nil
}

func (c *Clock) Health(ctx context.Context) Health {
	_ = ctx
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.stopped && !c.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: c.host.now()}
	case c.started:
		return Health{Status: HealthHealthy, Message: "ok", CheckedAt: c.host.now()}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: c.host.now()}
	}
}

// Now returns the current time when the adapter is started; zero time otherwise.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	started := c.started
	c.mu.Unlock()
	if !started {
		return time.Time{}
	}
	return c.host.now()
}

// --- otel-correlate (INT-002 lifecycle marker) ---

// OtelCorrelate is a lifecycle-only adapter that signals the host to enable
// jenkins_get_trace_refs / diagnose trace_refs enrichment. It does not open
// network connections, hold credentials, or export OTLP.
//
// Auth isolation: Host still has no Jenkins client. Extraction runs in the
// tools layer against build parameters already returned by the Jenkins client.
type OtelCorrelate struct {
	host    Host
	mu      sync.Mutex
	started bool
	stopped bool
}

// NewOtelCorrelate constructs the otel-correlate adapter.
func NewOtelCorrelate(host Host) (Adapter, error) {
	return &OtelCorrelate{host: host}, nil
}

func (o *OtelCorrelate) ID() string { return IDOtelCorrelate }

func (o *OtelCorrelate) Capabilities() []Capability {
	return []Capability{CapLifecycle, CapTelemetry}
}

func (o *OtelCorrelate) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	o.started = true
	o.stopped = false
	o.mu.Unlock()
	o.host.logf("adapter otel-correlate: started (correlation IDs only; no OTLP export)")
	return nil
}

func (o *OtelCorrelate) Stop(ctx context.Context) error {
	_ = ctx
	o.mu.Lock()
	o.stopped = true
	o.started = false
	o.mu.Unlock()
	o.host.logf("adapter otel-correlate: stopped")
	return nil
}

func (o *OtelCorrelate) Health(ctx context.Context) Health {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case o.stopped && !o.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: o.host.now()}
	case o.started:
		return Health{
			Status:    HealthHealthy,
			Message:   "correlation enabled (build metadata only; no OTLP)",
			CheckedAt: o.host.now(),
		}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: o.host.now()}
	}
}

// --- panic adapter (tests only; not in DefaultCatalog) ---

// PanicOnStart is a test double that panics in Start (not registered by default).
type PanicOnStart struct{}

func (p *PanicOnStart) ID() string                    { return "panic_start" }
func (p *PanicOnStart) Capabilities() []Capability    { return []Capability{CapLifecycle} }
func (p *PanicOnStart) Start(context.Context) error   { panic("intentional adapter panic") }
func (p *PanicOnStart) Stop(context.Context) error    { return nil }
func (p *PanicOnStart) Health(context.Context) Health { return Health{Status: HealthUnknown} }

// PanicOnHealth panics in Health.
type PanicOnHealth struct{}

func (p *PanicOnHealth) ID() string                    { return "panic_health" }
func (p *PanicOnHealth) Capabilities() []Capability    { return []Capability{CapLifecycle} }
func (p *PanicOnHealth) Start(context.Context) error   { return nil }
func (p *PanicOnHealth) Stop(context.Context) error    { return nil }
func (p *PanicOnHealth) Health(context.Context) Health { panic("intentional health panic") }
