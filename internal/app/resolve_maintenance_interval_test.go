package app_test

import (
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/app"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

// Wave 49 Track C / ARC-007: ResolveMaintenanceInterval default → env → flag,
// absolute min/max fail-closed, invalid and ≤0 rejected.
func TestResolveMaintenanceInterval_Default(t *testing.T) {
	t.Parallel()
	d, err := app.ResolveMaintenanceInterval("", "")
	if err != nil {
		t.Fatal(err)
	}
	if d != app.DefaultMaintenanceInterval {
		t.Fatalf("got %v want default %v", d, app.DefaultMaintenanceInterval)
	}
	// Whitespace-only is unset.
	d, err = app.ResolveMaintenanceInterval("  ", "\t")
	if err != nil || d != app.DefaultMaintenanceInterval {
		t.Fatalf("whitespace: got %v %v", d, err)
	}
}

func TestResolveMaintenanceInterval_Precedence(t *testing.T) {
	t.Parallel()
	// Env only.
	d, err := app.ResolveMaintenanceInterval("", "1m")
	if err != nil || d != time.Minute {
		t.Fatalf("env: got %v %v", d, err)
	}
	// Flag wins over env.
	d, err = app.ResolveMaintenanceInterval("45s", "1m")
	if err != nil || d != 45*time.Second {
		t.Fatalf("flag wins: got %v %v", d, err)
	}
	// Empty flag falls through to env.
	d, err = app.ResolveMaintenanceInterval("", "2m")
	if err != nil || d != 2*time.Minute {
		t.Fatalf("env fallback: got %v %v", d, err)
	}
	// Empty flag + empty env → default even if flag is whitespace.
	d, err = app.ResolveMaintenanceInterval(" ", "30m")
	if err != nil || d != 30*time.Minute {
		t.Fatalf("ws flag uses env: got %v %v", d, err)
	}
}

func TestResolveMaintenanceInterval_MinMaxBounds(t *testing.T) {
	t.Parallel()
	// At min / at absolute max accepted.
	d, err := app.ResolveMaintenanceInterval(app.MinMaintenanceInterval.String(), "")
	if err != nil || d != app.MinMaintenanceInterval {
		t.Fatalf("at min: %v %v", d, err)
	}
	d, err = app.ResolveMaintenanceInterval(app.AbsoluteMaxMaintenanceInterval.String(), "")
	if err != nil || d != app.AbsoluteMaxMaintenanceInterval {
		t.Fatalf("at max: %v %v", d, err)
	}
	// Default must sit inside the window.
	if app.DefaultMaintenanceInterval < app.MinMaintenanceInterval ||
		app.DefaultMaintenanceInterval > app.AbsoluteMaxMaintenanceInterval {
		t.Fatalf("default %v outside [%v, %v]",
			app.DefaultMaintenanceInterval, app.MinMaintenanceInterval, app.AbsoluteMaxMaintenanceInterval)
	}
	// Constant drift guards (Wave 49 contract).
	if app.MinMaintenanceInterval != 30*time.Second {
		t.Fatalf("MinMaintenanceInterval drift: %v", app.MinMaintenanceInterval)
	}
	if app.AbsoluteMaxMaintenanceInterval != time.Hour {
		t.Fatalf("AbsoluteMaxMaintenanceInterval drift: %v", app.AbsoluteMaxMaintenanceInterval)
	}
	if app.DefaultMaintenanceInterval != 5*time.Minute {
		t.Fatalf("DefaultMaintenanceInterval drift: %v", app.DefaultMaintenanceInterval)
	}
	if app.EnvCacheMaintenanceInterval != "JENKINS_MCP_CACHE_MAINTENANCE_INTERVAL" {
		t.Fatalf("env name drift: %q", app.EnvCacheMaintenanceInterval)
	}

	// Below min fail closed.
	_, err = app.ResolveMaintenanceInterval("29s", "")
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("below min: want invalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "minimum") {
		t.Fatalf("below min msg: %v", err)
	}
	// Above absolute max fail closed (absurd multi-day).
	_, err = app.ResolveMaintenanceInterval("", "48h")
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("above max: want invalid, got %v", err)
	}
	if !strings.Contains(err.Error(), "absolute maximum") && !strings.Contains(err.Error(), "maximum") {
		t.Fatalf("above max msg: %v", err)
	}
	// 1h1s over absolute.
	_, err = app.ResolveMaintenanceInterval("1h1s", "")
	if err == nil {
		t.Fatal("1h1s must fail closed")
	}
}

func TestResolveMaintenanceInterval_InvalidAndNonPositive(t *testing.T) {
	t.Parallel()
	// Unparseable.
	_, err := app.ResolveMaintenanceInterval("not-a-duration", "")
	if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("invalid flag: %v", err)
	}
	if !strings.Contains(err.Error(), "flag") {
		t.Fatalf("should name flag source: %v", err)
	}
	_, err = app.ResolveMaintenanceInterval("", "5") // bare number without unit
	if err == nil {
		t.Fatal("bare number must fail")
	}
	// Source layer is "env …"; full env var name may be [REDACTED] by bare-token
	// heuristic (long JENKINS_MCP_* identifiers) — assert layer label only.
	if !strings.Contains(err.Error(), "env") {
		t.Fatalf("should name env source layer: %v", err)
	}
	// ≤0 fail closed (not treated as default).
	for _, raw := range []string{"0", "0s", "-1m", "-30s"} {
		_, err := app.ResolveMaintenanceInterval(raw, "")
		if err == nil || apperr.CodeOf(err) != apperr.CodeInvalidArgument {
			t.Fatalf("%q: want invalid, got %v", raw, err)
		}
	}
	// Bad env fails even when flag would win (validate env layer first).
	_, err = app.ResolveMaintenanceInterval("5m", "not-duration")
	if err == nil {
		t.Fatal("invalid env must fail closed even with valid flag")
	}
}

// Regression: multi-day intervals must not be accepted (pre-Wave-49 allowed any positive).
func TestResolveMaintenanceInterval_RegressionAbsurdInterval(t *testing.T) {
	t.Parallel()
	// Regression: operator could set multi-day intervals with no absolute max.
	_, err := app.ResolveMaintenanceInterval("168h", "") // 7 days
	if err == nil {
		t.Fatal("Regression: multi-day cache-maintenance-interval must fail closed")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("want CodeInvalidArgument, got %v", err)
	}
	// Error must not look like a secret dump.
	msg := err.Error()
	if strings.Contains(msg, "token") || strings.Contains(msg, "password") {
		t.Fatalf("secret-like error: %q", msg)
	}
}
