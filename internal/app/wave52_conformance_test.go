package app_test

import (
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/app"
)

// Wave 52 / ARC-007 cache maintenance conformance (Track D):
//   - Hard-assert Wave 49 Done* ResolveMaintenanceInterval absolute fail-closed
//     resolve (default 5m, min 30s, absolute 1h) — retention through Wave 52
//   - Soft residual note: Wave 52 feature tracks A/B/C live in mutation/tools/
//     diagnostics (confirm cooldown resolve, min/abs backoff operator_caps,
//     max previews/minute resolve) — no new app package symbols expected

// TestWave52_Wave49Done_ResolveMaintenanceInterval_Hard hard-asserts Wave 49
// Track C Done*: ResolveMaintenanceInterval default 5m, min 30s, absolute 1h,
// flag wins over env, fail-closed below min / above absolute / non-positive /
// invalid. Must remain true after Wave 52 parallel tracks merge.
func TestWave52_Wave49Done_ResolveMaintenanceInterval_Hard(t *testing.T) {
	t.Parallel()

	if app.DefaultMaintenanceInterval != 5*time.Minute {
		t.Fatalf("DefaultMaintenanceInterval=%v want 5m", app.DefaultMaintenanceInterval)
	}
	if app.MinMaintenanceInterval != 30*time.Second {
		t.Fatalf("MinMaintenanceInterval=%v want 30s", app.MinMaintenanceInterval)
	}
	if app.AbsoluteMaxMaintenanceInterval != 1*time.Hour {
		t.Fatalf("AbsoluteMaxMaintenanceInterval=%v want 1h", app.AbsoluteMaxMaintenanceInterval)
	}
	if app.EnvCacheMaintenanceInterval != "JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL" {
		t.Fatalf("env name: %q", app.EnvCacheMaintenanceInterval)
	}

	d, err := app.ResolveMaintenanceInterval("", "")
	if err != nil || d != app.DefaultMaintenanceInterval {
		t.Fatalf("default resolve: d=%v err=%v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval("", "1m")
	if err != nil || d != time.Minute {
		t.Fatalf("env only: d=%v err=%v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval("45s", "1m")
	if err != nil || d != 45*time.Second {
		t.Fatalf("flag wins: d=%v err=%v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval(app.MinMaintenanceInterval.String(), "")
	if err != nil || d != app.MinMaintenanceInterval {
		t.Fatalf("at min: d=%v err=%v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval(app.AbsoluteMaxMaintenanceInterval.String(), "")
	if err != nil || d != app.AbsoluteMaxMaintenanceInterval {
		t.Fatalf("at absolute: d=%v err=%v", d, err)
	}
	if _, err := app.ResolveMaintenanceInterval("29s", ""); err == nil {
		t.Fatal("below min must fail closed")
	}
	if _, err := app.ResolveMaintenanceInterval("", "48h"); err == nil {
		t.Fatal("above absolute must fail closed")
	}
	if _, err := app.ResolveMaintenanceInterval("0", ""); err == nil {
		t.Fatal("zero must fail closed")
	}
	if _, err := app.ResolveMaintenanceInterval("0s", ""); err == nil {
		t.Fatal("0s must fail closed")
	}
	if _, err := app.ResolveMaintenanceInterval("not-a-duration", ""); err == nil {
		t.Fatal("invalid parse must fail closed")
	}

	// EffectiveInterval retention: zero Interval → default; positive → as configured.
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

// TestWave52_SoftResidual_AppLayerNote records that Wave 52 residual tracks
// (ResolveConfirmCooldown, operator_caps min/abs backoff ms, ResolveMaxPreviewsPerMinute)
// are mutation/tools/diagnostics concerns — app package has no new symbols for
// them. Soft residual only; never fails for absence of those features.
func TestWave52_SoftResidual_AppLayerNote(t *testing.T) {
	t.Parallel()
	t.Logf("Wave 52 soft residual (app): ResolveMaintenanceInterval hard-asserted "+
		"(DefaultMaintenanceInterval=%s); Track A ResolveConfirmCooldown / "+
		"Track B operator_caps min/abs backoff ms / Track C ResolveMaxPreviewsPerMinute "+
		"are mutation/tools residuals (planned/in progress; not claimed Done* by Track D)",
		app.DefaultMaintenanceInterval)
}
