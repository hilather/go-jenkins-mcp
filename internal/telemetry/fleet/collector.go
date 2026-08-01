package fleet

import (
	"context"
	"sync"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/config"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// DefaultSnapshotInterval is the low-frequency health snapshot period during serve.
const DefaultSnapshotInterval = 5 * time.Minute

// Collector periodically snapshots metrics into the local queue and optionally
// exports. All work is best-effort: errors never fail the serve path.
type Collector struct {
	mu       sync.Mutex
	paths    config.Paths
	metrics  *telemetry.Metrics
	queue    *Queue
	exporter *Exporter
	install  string
	version  string
	profile  string
	authMeth string
	readOnly bool
	interval time.Duration
	// forceOff models enterprise pin (overlay fleet_telemetry_force_off).
	// Guarded by mu for hot-reload SetForceOff.
	forceOff bool
	// lastSnap holds the most recent in-process event for show/status without disk.
	lastSnap *Event
	stopped  bool
}

// CollectorConfig wires serve-time fleet telemetry (MGR-002).
type CollectorConfig struct {
	Paths      config.Paths
	Metrics    *telemetry.Metrics
	Version    string
	ProfileID  string
	AuthMethod string
	// ReadOnly is the effective global read-only gate (exported as bool).
	ReadOnly bool
	// Interval defaults to DefaultSnapshotInterval.
	Interval time.Duration
	// Queue optional; created under Paths when nil and enabled.
	Queue *Queue
	// Exporter optional; built from env URL when nil.
	Exporter *Exporter
	// ForceOff disables even when env is set (enterprise overlay pin
	// fleet_telemetry_force_off). When true at NewCollector, returns nil.
	// Live collectors honor SetForceOff for mid-session hot-reload.
	ForceOff bool
	// Enabled overrides env when non-nil (tests).
	Enabled *bool
}

// NewCollector builds a collector. Returns nil, nil when telemetry is disabled
// so callers can skip Start without error.
func NewCollector(cfg CollectorConfig) (*Collector, error) {
	enabled := EnabledFromEnv()
	if cfg.Enabled != nil {
		enabled = *cfg.Enabled
	}
	if cfg.ForceOff {
		enabled = false
	}
	if !enabled {
		return nil, nil
	}
	q := cfg.Queue
	if q == nil {
		var err error
		q, err = NewQueueFromPaths(cfg.Paths)
		if err != nil {
			// Queue open failure: do not fail serve — return disabled collector.
			return nil, nil
		}
	}
	install, err := CachedInstallationID(cfg.Paths)
	if err != nil {
		// Install id failure: continue with empty id (still local-only useful).
		install = ""
	}
	exp := cfg.Exporter
	if exp == nil {
		exp = NewExporter(ExporterConfig{URL: ExportURLFromEnv()})
	}
	interval := cfg.Interval
	if interval <= 0 {
		interval = DefaultSnapshotInterval
	}
	return &Collector{
		paths:    cfg.Paths,
		metrics:  cfg.Metrics,
		queue:    q,
		exporter: exp,
		install:  install,
		version:  cfg.Version,
		profile:  cfg.ProfileID,
		authMeth: cfg.AuthMethod,
		readOnly: cfg.ReadOnly,
		interval: interval,
		forceOff: cfg.ForceOff,
	}, nil
}

// Start runs snapshot + export loops until ctx is cancelled.
// Safe to call on nil (disabled). Never returns a fatal error to serve.
func (c *Collector) Start(ctx context.Context) {
	if c == nil {
		return
	}
	// Immediate first snapshot so status/show have data without waiting.
	c.SnapshotOnce()
	go c.loop(ctx)
}

func (c *Collector) loop(ctx context.Context) {
	snapTicker := time.NewTicker(c.interval)
	defer snapTicker.Stop()
	// Export attempts more frequently but respect exporter backoff.
	exportTicker := time.NewTicker(30 * time.Second)
	defer exportTicker.Stop()
	var nextExport time.Time

	for {
		select {
		case <-ctx.Done():
			c.mu.Lock()
			c.stopped = true
			c.mu.Unlock()
			return
		case <-snapTicker.C:
			c.SnapshotOnce()
		case <-exportTicker.C:
			if c.ForceOff() {
				continue
			}
			if c.exporter == nil || !c.exporter.URLConfigured() {
				continue
			}
			now := time.Now()
			if now.Before(nextExport) {
				continue
			}
			// Isolate network from serve: short timeout, ignore errors.
			ectx, cancel := context.WithTimeout(ctx, 20*time.Second)
			_, err := c.exporter.DrainAndExport(ectx, c.queue, 16)
			cancel()
			if err != nil {
				nextExport = time.Now().Add(c.exporter.CurrentBackoff())
			} else {
				nextExport = time.Time{}
			}
		}
	}
}

// SnapshotOnce builds an event from current metrics and enqueues it.
// Nil-safe; never panics; never returns errors to the serve path.
// No-ops when force-off is set (enterprise pin / hot-reload).
func (c *Collector) SnapshotOnce() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if c.forceOff || c.stopped {
		c.mu.Unlock()
		return
	}
	install, profile, version, authMeth, readOnly := c.install, c.profile, c.version, c.authMeth, c.readOnly
	metrics, q := c.metrics, c.queue
	c.mu.Unlock()
	// Pass full counter map; BuildEvent allowlists counters and extracts error:* codes.
	// Do not hold c.mu across metrics.Snapshot or Enqueue.
	var counters map[string]int64
	if metrics != nil {
		counters = metrics.Snapshot().Counters
	}
	ev := BuildEvent(BuildOptions{
		InstallationID: install,
		ProfileID:      profile,
		Version:        version,
		AuthMethod:     authMeth,
		ReadOnly:       readOnly,
		Counters:       counters,
	})
	c.mu.Lock()
	if c.forceOff || c.stopped {
		c.mu.Unlock()
		return
	}
	c.lastSnap = &ev
	c.mu.Unlock()
	if q != nil {
		_ = q.Enqueue(ev)
	}
}

// SetForceOff hot-applies enterprise fleet_telemetry_force_off (MGR-002).
// When true, further snapshots and exports are suppressed; env cannot re-enable
// until SetForceOff(false). Nil-safe. True wins for the process until cleared.
func (c *Collector) SetForceOff(forceOff bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.forceOff = forceOff
	c.mu.Unlock()
}

// ForceOff reports whether enterprise force-off is currently applied.
// Nil collector reports false (no pin); use EffectiveEnabled for enablement.
func (c *Collector) ForceOff() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.forceOff
}

// LastEvent returns the most recent in-process snapshot, if any.
func (c *Collector) LastEvent() *Event {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.lastSnap == nil {
		return nil
	}
	cp := *c.lastSnap
	return &cp
}

// Queue returns the underlying queue (may be nil when disabled).
func (c *Collector) Queue() *Queue {
	if c == nil {
		return nil
	}
	return c.queue
}

// Enabled reports whether this collector is active and not force-off'd.
func (c *Collector) Enabled() bool {
	if c == nil {
		return false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return !c.forceOff
}
