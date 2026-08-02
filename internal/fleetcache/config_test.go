package fleetcache_test

import (
	"strings"
	"testing"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/fleetcache"
)

func TestResolveConfig_DefaultOff(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		Getenv: func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != fleetcache.ModeOff || cfg.Active() {
		t.Fatalf("default must be off: %+v", cfg)
	}
	if !cfg.OriginFallback {
		t.Fatal("origin fallback must be true")
	}
	if cfg.PeerLookupTimeout != fleetcache.DefaultPeerLookupTimeout {
		t.Fatalf("lookup default: %v", cfg.PeerLookupTimeout)
	}
	if cfg.MaxPeerStreams != fleetcache.DefaultMaxPeerStreams {
		t.Fatalf("streams default: %d", cfg.MaxPeerStreams)
	}
	if cfg.MaxPeerLookups != fleetcache.DefaultMaxPeerLookups {
		t.Fatalf("lookups default: %d", cfg.MaxPeerLookups)
	}
}

func TestResolveConfig_ModesAndBudgets(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		ModeFlag:              "read",
		PeerLookupTimeoutFlag: "200ms",
		MaxPeerStreamsFlag:    "8",
		MaxPeerLookupsFlag:    "3",
		Getenv:                func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != fleetcache.ModeRead || !cfg.PeerIOEnabled() {
		t.Fatalf("%+v", cfg)
	}
	if cfg.PeerLookupTimeout != 200*time.Millisecond {
		t.Fatalf("timeout %v", cfg.PeerLookupTimeout)
	}
	if cfg.MaxPeerStreams != 8 || cfg.MaxPeerLookups != 3 {
		t.Fatalf("%+v", cfg)
	}
}

func TestResolveConfig_EmptyZeroMeansDefault(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		ModeFlag:              "shadow",
		PeerLookupTimeoutFlag: "0",
		MaxPeerStreamsFlag:    "0",
		Getenv:                func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerLookupTimeout != fleetcache.DefaultPeerLookupTimeout {
		t.Fatalf("got %v", cfg.PeerLookupTimeout)
	}
	if cfg.MaxPeerStreams != fleetcache.DefaultMaxPeerStreams {
		t.Fatalf("streams %d", cfg.MaxPeerStreams)
	}
	if cfg.Mode != fleetcache.ModeShadow || cfg.PeerIOEnabled() {
		t.Fatalf("shadow must not enable peer I/O: %+v", cfg)
	}
}

func TestResolveConfig_FailClosed(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		opts fleetcache.ResolveOptions
	}{
		{"bad mode", fleetcache.ResolveOptions{ModeFlag: "on", Getenv: func(string) string { return "" }}},
		{"neg timeout", fleetcache.ResolveOptions{PeerLookupTimeoutFlag: "-1ms", Getenv: func(string) string { return "" }}},
		{"timeout too small", fleetcache.ResolveOptions{PeerLookupTimeoutFlag: "1ms", Getenv: func(string) string { return "" }}},
		{"timeout too large", fleetcache.ResolveOptions{PeerLookupTimeoutFlag: "30s", Getenv: func(string) string { return "" }}},
		{"streams too high", fleetcache.ResolveOptions{MaxPeerStreamsFlag: "999", Getenv: func(string) string { return "" }}},
		{"lookups negative", fleetcache.ResolveOptions{MaxPeerLookupsFlag: "-2", Getenv: func(string) string { return "" }}},
		{"origin off", fleetcache.ResolveOptions{Getenv: func(k string) string {
			if k == fleetcache.EnvOriginFallback {
				return "false"
			}
			return ""
		}}},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := fleetcache.ResolveConfig(tc.opts)
			if err == nil {
				t.Fatal("expected error")
			}
			if apperr.CodeOf(err) != apperr.CodeInvalidArgument && apperr.CodeOf(err) != apperr.CodeInternal {
				// invalid_argument expected for operator mistakes
				if apperr.CodeOf(err) == "" {
					t.Fatalf("want typed error: %v", err)
				}
			}
		})
	}
}

func TestResolveConfig_FlagWinsOverEnv(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		ModeFlag: "full",
		Getenv: func(k string) string {
			if k == fleetcache.EnvMode {
				return "off"
			}
			return ""
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Mode != fleetcache.ModeFull {
		t.Fatalf("flag must win: %v", cfg.Mode)
	}
}

func TestResolveConfig_MillisInteger(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		PeerLookupTimeoutFlag: "500",
		Getenv:                func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PeerLookupTimeout != 500*time.Millisecond {
		t.Fatalf("got %v", cfg.PeerLookupTimeout)
	}
}

func TestConfig_StatusSummary_DefaultOffHandlersLibraryLive(t *testing.T) {
	t.Parallel()
	cfg, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{Getenv: func(string) string { return "" }})
	if err != nil {
		t.Fatal(err)
	}
	st := cfg.StatusSummary()
	// Default mode remains off even though FLC-030/031 handler libraries exist.
	if st["mode"] != "off" || st["active"] != false {
		t.Fatalf("%+v", st)
	}
	if st["peer_read_handlers_live"] != true {
		t.Fatalf("handlers library live: %+v", st)
	}
	if st["peer_read_handlers"] != "lookup_decoded_read_frame_export" {
		t.Fatalf("%+v", st)
	}
	// FLC-061: process-local metrics aggregation residual (multi-member = FLC-062+).
	if st["aggregation"] != fleetcache.MetricsAggregationResidual {
		t.Fatalf("aggregation residual: %+v", st["aggregation"])
	}
	// Residual honesty: epic Done* offline; object_classes observable; no production-on-by-default.
	res, _ := st["residual"].(string)
	if res == "" {
		t.Fatal("missing residual")
	}
	if !strings.Contains(res, "default mode off") {
		t.Fatalf("residual must keep mode off: %q", res)
	}
	if !strings.Contains(res, "console_log") && !strings.Contains(fmtString(st["object_classes"]), "console_log") {
		t.Fatalf("object class residual missing: residual=%q classes=%v", res, st["object_classes"])
	}
	if strings.Contains(res, "production GO") && !strings.Contains(res, "residual") {
		t.Fatalf("must not claim production GO: %q", res)
	}
	cfg2, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		ModeFlag: "read",
		Getenv:   func(string) string { return "" },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !cfg2.PeerIOEnabled() || !cfg2.PeerReadHandlersLive() {
		t.Fatal("mode=read enables peer I/O and reports handlers library live")
	}
	st2 := cfg2.StatusSummary()
	if st2["peer_read_handlers_live"] != true {
		t.Fatalf("%+v", st2)
	}
	for _, v := range st2 {
		s, ok := v.(string)
		if !ok {
			continue
		}
		if strings.Contains(strings.ToLower(s), "token=") || strings.Contains(s, "Bearer ") {
			t.Fatalf("secret-like status: %q", s)
		}
	}
}

func TestResolveConfig_MessagesSecretFree(t *testing.T) {
	t.Parallel()
	_, err := fleetcache.ResolveConfig(fleetcache.ResolveOptions{
		ModeFlag: "nope",
		Getenv:   func(string) string { return "" },
	})
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	for _, bad := range []string{"password", "token=", "Bearer "} {
		if strings.Contains(strings.ToLower(msg), strings.ToLower(bad)) {
			t.Fatalf("secret-like message: %q", msg)
		}
	}
}
