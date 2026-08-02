package app_test

import (
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/app"
)

// Wave 49 / ARC-007 cache maintenance conformance (Track D):
//   - Hard-assert DefaultMaintenanceInterval remains 5m (Wave 48-era serve default)
//   - Soft residual for Wave 49 Track C ResolveMaintenanceInterval absolute
//     resolve — t.Log if symbols missing (never fail for absence; Track C planned /
//     not claimed Done* by Track D)

// TestWave49_DefaultMaintenanceInterval_Hard hard-asserts package default tick
// interval is 5 minutes and EffectiveInterval falls back correctly. Must remain
// true after Wave 49 parallel tracks merge (Track C absolute resolve must not
// silently change the default).
func TestWave49_DefaultMaintenanceInterval_Hard(t *testing.T) {
	t.Parallel()

	if app.DefaultMaintenanceInterval != 5*time.Minute {
		t.Fatalf("DefaultMaintenanceInterval=%v want 5m", app.DefaultMaintenanceInterval)
	}
	if app.DefaultMaintenanceInterval <= 0 {
		t.Fatalf("DefaultMaintenanceInterval must be positive, got %v", app.DefaultMaintenanceInterval)
	}

	// EffectiveInterval: zero Interval → default; positive Interval → as configured.
	cfg := app.MaintenanceConfig{}
	if got := cfg.EffectiveInterval(); got != app.DefaultMaintenanceInterval {
		t.Fatalf("EffectiveInterval zero Interval: got %v want %v", got, app.DefaultMaintenanceInterval)
	}
	cfg.Interval = 2 * time.Minute
	if got := cfg.EffectiveInterval(); got != 2*time.Minute {
		t.Fatalf("EffectiveInterval explicit: got %v want 2m", got)
	}

	def := app.DefaultMaintenanceConfig()
	if def.Interval != app.DefaultMaintenanceInterval {
		t.Fatalf("DefaultMaintenanceConfig.Interval=%v want %v", def.Interval, app.DefaultMaintenanceInterval)
	}
}

// TestWave49_SoftResidual_TrackC_ResolveMaintenanceInterval is a compile-safe soft
// residual note for Wave 49 Track C ResolveMaintenanceInterval (absolute fail-closed
// serve resolve for --cache-maintenance-interval / env). Symbols are not present on
// current main (CLI still uses parseCacheMaintenanceInterval in cmd). Soft residual
// only — never fails for absence; Track C not claimed Done* by Track D.
func TestWave49_SoftResidual_TrackC_ResolveMaintenanceInterval(t *testing.T) {
	t.Parallel()
	// Planned Track C surface (not claimed Done* by Track D):
	//   ResolveMaintenanceInterval(flag, env) → duration
	//   AbsoluteMaxMaintenanceInterval / EnvCacheMaintenanceInterval
	// Soft residual: t.Log only so this package compiles and passes without C.
	// If Track C later exports ResolveMaintenanceInterval on package app, a
	// follow-up hard assert may land in Wave 50 Track D — not here.
	t.Logf("Wave 49 soft residual Track C: ResolveMaintenanceInterval planned "+
		"(DefaultMaintenanceInterval=%s hard-asserted; absolute resolve not yet present; "+
		"Track C planned/in progress; not a failure)",
		app.DefaultMaintenanceInterval)
}
