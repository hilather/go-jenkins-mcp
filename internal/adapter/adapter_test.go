package adapter_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/adapter"
	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
)

func TestDisabledByDefault(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Fatalf("expected no adapters registered by default, got %d: %v", r.Len(), r.IDs())
	}
	if err := r.StartAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 0 {
		t.Fatal("start should not invent adapters")
	}
	h := r.Health(context.Background(), adapter.IDClock)
	if h.Status != adapter.HealthDisabled {
		t.Fatalf("status=%s want disabled", h.Status)
	}
}

func TestFailRegistrationUnknownID(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{"splunk-prod"},
		Allowlist:  adapter.AllowlistFromIDs("splunk-prod"), // approved but not in catalog
	})
	err := r.RegisterEnabled()
	if err == nil {
		t.Fatal("expected unknown id error")
	}
	if apperr.CodeOf(err) != apperr.CodeInvalidArgument {
		t.Fatalf("code=%s err=%v", apperr.CodeOf(err), err)
	}
	if !strings.Contains(err.Error(), "unknown adapter") {
		t.Fatalf("err=%v", err)
	}
	if r.Len() != 0 {
		t.Fatalf("partial register: %v", r.IDs())
	}
}

func TestFailRegistrationNotOnAllowlist(t *testing.T) {
	t.Parallel()
	falseV := false
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs:    []string{adapter.IDClock},
		Allowlist:     adapter.EmptyAllowlist(),
		AllowBuiltins: &falseV,
	})
	err := r.RegisterEnabled()
	if err == nil {
		t.Fatal("expected allowlist denial")
	}
	if apperr.CodeOf(err) != apperr.CodePolicyDenial {
		t.Fatalf("code=%s err=%v", apperr.CodeOf(err), err)
	}
}

func TestEnableBuiltinClock(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDClock},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if r.Len() != 1 {
		t.Fatalf("len=%d", r.Len())
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	h := r.Health(ctx, adapter.IDClock)
	if h.Status != adapter.HealthHealthy {
		t.Fatalf("health=%+v", h)
	}
	entry := r.Get(adapter.IDClock)
	if entry == nil {
		t.Fatal("missing entry")
	}
	clk, ok := entry.Adapter.(*adapter.Clock)
	if !ok {
		t.Fatalf("type %T", entry.Adapter)
	}
	if clk.Now().IsZero() {
		t.Fatal("clock Now should be non-zero when started")
	}
	if err := r.StopAll(ctx); err != nil {
		t.Fatal(err)
	}
	h = r.Health(ctx, adapter.IDClock)
	if h.Status != adapter.HealthStopped {
		t.Fatalf("after stop health=%+v", h)
	}
}

func TestAllowlistFile(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "allow.json")
	if err := os.WriteFile(path, []byte(`{"approved":["noop"],"version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	al, err := adapter.LoadAllowlistFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !al.Contains(adapter.IDNoop) || al.Contains(adapter.IDClock) {
		t.Fatalf("allowlist: noop=%v clock=%v", al.Contains(adapter.IDNoop), al.Contains(adapter.IDClock))
	}
	falseV := false
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs:    []string{adapter.IDNoop},
		Allowlist:     al,
		AllowBuiltins: &falseV,
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	// clock not allowed
	r2 := adapter.NewRegistry(adapter.Config{
		EnabledIDs:    []string{adapter.IDClock},
		Allowlist:     al,
		AllowBuiltins: &falseV,
	})
	if err := r2.RegisterEnabled(); err == nil {
		t.Fatal("clock should be denied")
	}
}

func TestPanicIsolationStart(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		// RegisterInstance with requireCatalog=false for panic double.
		Allowlist: adapter.AllowlistFromIDs("panic_start"),
	})
	if err := r.RegisterInstance(&adapter.PanicOnStart{}, false); err != nil {
		t.Fatal(err)
	}
	// StartAll must not panic the test process.
	err := r.StartAll(context.Background())
	if err == nil {
		t.Fatal("expected start error from panic")
	}
	h := r.Health(context.Background(), "panic_start")
	if h.Status != adapter.HealthUnhealthy {
		t.Fatalf("status=%s msg=%s", h.Status, h.Message)
	}
	if !strings.Contains(h.Message, "panic") {
		t.Fatalf("message should mention panic: %s", h.Message)
	}
}

func TestPanicIsolationHealth(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		Allowlist: adapter.AllowlistFromIDs("panic_health"),
	})
	if err := r.RegisterInstance(&adapter.PanicOnHealth{}, false); err != nil {
		t.Fatal(err)
	}
	if err := r.StartAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	// Health query must not panic the process.
	h := r.Health(context.Background(), "panic_health")
	if h.Status != adapter.HealthUnhealthy {
		t.Fatalf("status=%+v", h)
	}
}

func TestCallRateLimit(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs:     []string{adapter.IDNoop},
		RateCapacity:   1,
		RateRefillPerS: 0.0001, // effectively no refill in this test
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	if err := r.StartAll(context.Background()); err != nil {
		t.Fatal(err)
	}
	entry := r.Get(adapter.IDNoop)
	if entry == nil || entry.RateLimit == nil {
		t.Fatal("expected rate limit")
	}
	// Freeze clock so refill does not restore tokens mid-test.
	fixed := time.Unix(1_700_000_000, 0)
	entry.RateLimit.SetNow(func() time.Time { return fixed })

	if err := adapter.Call(entry, func() error { return nil }); err != nil {
		t.Fatalf("first call: %v", err)
	}
	err := adapter.Call(entry, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("second call want rate limited, got %v", err)
	}
}

func TestDefaultRateLimitForExtLogsBackend(t *testing.T) {
	t.Parallel()
	cap0, refill0 := adapter.DefaultRateLimitForExtLogsBackend(adapter.ExtLogsBackendNoop)
	if cap0 != 0 || refill0 != 0 {
		t.Fatalf("noop want unlimited (0,0), got (%v,%v)", cap0, refill0)
	}
	capEmpty, refillEmpty := adapter.DefaultRateLimitForExtLogsBackend("")
	if capEmpty != 0 || refillEmpty != 0 {
		t.Fatalf("empty want unlimited, got (%v,%v)", capEmpty, refillEmpty)
	}
	for _, backend := range []adapter.ExtLogsBackendName{
		adapter.ExtLogsBackendHTTP,
		adapter.ExtLogsBackendMock,
		"HTTP", // case-insensitive
	} {
		c, r := adapter.DefaultRateLimitForExtLogsBackend(backend)
		if c != adapter.DefaultNetworkAdapterRateCapacity {
			t.Fatalf("backend %q capacity=%v want %v", backend, c, adapter.DefaultNetworkAdapterRateCapacity)
		}
		if r != adapter.DefaultNetworkAdapterRateRefillPerS {
			t.Fatalf("backend %q refill=%v want %v", backend, r, adapter.DefaultNetworkAdapterRateRefillPerS)
		}
	}
}

// Default network rates must wire onto registry entries when RateCapacity is set
// (serve applies DefaultRateLimitForExtLogsBackend for non-noop ext-logs).
func TestRegistryAppliesDefaultNetworkRateLimit(t *testing.T) {
	t.Parallel()
	cap, refill := adapter.DefaultRateLimitForExtLogsBackend(adapter.ExtLogsBackendHTTP)
	if cap <= 0 {
		t.Fatal("http defaults must be positive")
	}
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs:     []string{adapter.IDExtLogs},
		RateCapacity:   cap,
		RateRefillPerS: refill,
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	entry := r.Get(adapter.IDExtLogs)
	if entry == nil {
		t.Fatal("missing ext-logs entry")
	}
	if entry.RateLimit == nil {
		t.Fatal("expected RateLimit on registry entry when RateCapacity > 0")
	}
	// Exhaust burst then assert throttle.
	fixed := time.Unix(1_700_000_000, 0)
	entry.RateLimit.SetNow(func() time.Time { return fixed })
	for i := 0; i < int(cap); i++ {
		if err := adapter.Call(entry, func() error { return nil }); err != nil {
			t.Fatalf("call %d within capacity: %v", i, err)
		}
	}
	err := adapter.Call(entry, func() error { return nil })
	if err == nil || !strings.Contains(err.Error(), "rate limited") {
		t.Fatalf("want rate limited after capacity, got %v", err)
	}
}

func TestCallPanicIsolation(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{EnabledIDs: []string{adapter.IDNoop}})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	entry := r.Get(adapter.IDNoop)
	err := adapter.Call(entry, func() error {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected panic error")
	}
	// Registry Health prefers prior panic over adapter self-report.
	h := r.Health(context.Background(), adapter.IDNoop)
	if h.Status != adapter.HealthUnhealthy {
		t.Fatalf("status=%s msg=%s", h.Status, h.Message)
	}
	if !strings.Contains(h.Message, "panic") && !strings.Contains(err.Error(), "panic") {
		t.Fatalf("expected panic signal: health=%+v err=%v", h, err)
	}
}

func TestOtelCorrelateBuiltin(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{
		EnabledIDs: []string{adapter.IDOtelCorrelate},
	})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := r.StartAll(ctx); err != nil {
		t.Fatal(err)
	}
	e := r.Get(adapter.IDOtelCorrelate)
	if e == nil {
		t.Fatal("expected otel-correlate entry")
	}
	caps := e.Capabilities
	var sawTel bool
	for _, c := range caps {
		if c == adapter.CapTelemetry {
			sawTel = true
		}
	}
	if !sawTel {
		t.Fatalf("want CapTelemetry, got %v", caps)
	}
	h := r.Health(ctx, adapter.IDOtelCorrelate)
	if h.Status != adapter.HealthHealthy {
		t.Fatalf("health=%+v", h)
	}
	if !strings.Contains(h.Message, "no OTLP") {
		t.Fatalf("health message should mention no OTLP: %s", h.Message)
	}
}

func TestAuthIsolation_HostHasNoJenkins(t *testing.T) {
	t.Parallel()
	// Structural: Host type fields must not include Jenkins or keyring.
	// Reflect-free check: package-level documentation contract + compile-time
	// zero Host construction in factory.
	var host adapter.Host
	a, err := adapter.NewNoop(host)
	if err != nil {
		t.Fatal(err)
	}
	if a.ID() != adapter.IDNoop {
		t.Fatal(a.ID())
	}
	// Catalog factories only accept Host — cannot pass *jenkins.Client without
	// changing the Factory signature (depgraph also enforces package edges).
}

func TestStartCancelled(t *testing.T) {
	t.Parallel()
	r := adapter.NewRegistry(adapter.Config{EnabledIDs: []string{adapter.IDNoop}})
	if err := r.RegisterEnabled(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := r.StartAll(ctx)
	if err == nil {
		t.Fatal("expected cancel error")
	}
}

func TestLoadAllowlistEmptyPath(t *testing.T) {
	t.Parallel()
	al, err := adapter.LoadAllowlistFile("")
	if err != nil {
		t.Fatal(err)
	}
	if al.Contains(adapter.IDNoop) {
		t.Fatal("empty path must deny")
	}
}

func TestLoadAllowlistMissingFileFailsClosed(t *testing.T) {
	t.Parallel()
	_, err := adapter.LoadAllowlistFile(filepath.Join(t.TempDir(), "nope.json"))
	if err == nil {
		t.Fatal("expected error")
	}
}
