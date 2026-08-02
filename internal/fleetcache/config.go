package fleetcache

import (
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// Mode is the fleet-cache rollout mode (ADR 0016).
type Mode string

const (
	// ModeOff is the product default: local plane A only (no peer cache I/O).
	ModeOff Mode = "off"
	// ModeShadow computes placement/metrics only; no peer read/write.
	ModeShadow Mode = "shadow"
	// ModeRead enables owner-directed peer read of sealed logs (MVP A).
	ModeRead Mode = "read"
	// ModeFull enables fill + RF2 + repair (later gate; accepted in config only).
	ModeFull Mode = "full"
)

// Env keys (flag wins over env when both set at a higher layer).
const (
	EnvMode              = "JENKINS_MCP_FLEET_CACHE_MODE"
	EnvPeerLookupTimeout = "JENKINS_MCP_FLEET_CACHE_PEER_LOOKUP_TIMEOUT"
	EnvMaxPeerStreams    = "JENKINS_MCP_FLEET_CACHE_MAX_PEER_STREAMS"
	EnvMaxPeerLookups    = "JENKINS_MCP_FLEET_CACHE_MAX_PEER_LOOKUPS"
	EnvOriginFallback    = "JENKINS_MCP_FLEET_CACHE_ORIGIN_FALLBACK" // always true unless invalid
)

// Product defaults (SLOs: docs/fleet/shared-cache-slos.md).
const (
	// DefaultPeerLookupTimeout is the max wait for peer owner lookup before origin fallback.
	DefaultPeerLookupTimeout = 750 * time.Millisecond
	// MinPeerLookupTimeout is the smallest explicit timeout operators may set.
	MinPeerLookupTimeout = 50 * time.Millisecond
	// MaxPeerLookupTimeout is the largest allowed peer lookup budget (fail closed above).
	MaxPeerLookupTimeout = 5 * time.Second

	// DefaultMaxPeerStreams is concurrent pure-frame streams per process.
	DefaultMaxPeerStreams = 4
	// MinMaxPeerStreams is the smallest explicit stream cap.
	MinMaxPeerStreams = 1
	// AbsoluteMaxPeerStreams is the hard process ceiling.
	AbsoluteMaxPeerStreams = 32

	// DefaultMaxPeerLookups is concurrent owner HEAD/lookup attempts.
	DefaultMaxPeerLookups = 2
	// MinMaxPeerLookups smallest explicit lookup concurrency.
	MinMaxPeerLookups = 1
	// AbsoluteMaxPeerLookups hard ceiling.
	AbsoluteMaxPeerLookups = 16
)

// Config is resolved fleet-cache operator configuration.
// Zero-value Mode is treated as ModeOff by Active().
type Config struct {
	Mode Mode
	// PeerLookupTimeout bounds owner-directed lookup before authorized origin fallback.
	PeerLookupTimeout time.Duration
	// MaxPeerStreams caps concurrent compressed frame streams (import/export).
	MaxPeerStreams int
	// MaxPeerLookups caps concurrent owner lookup/read attempts for one request.
	MaxPeerLookups int
	// OriginFallback is always true when resolved successfully (degraded cache must not block origin).
	OriginFallback bool
}

// ResolveOptions are operator inputs for ResolveConfig.
type ResolveOptions struct {
	ModeFlag              string
	PeerLookupTimeoutFlag string
	MaxPeerStreamsFlag    string
	MaxPeerLookupsFlag    string
	// Getenv optional (default os.Getenv).
	Getenv func(string) string
}

// ResolveConfig resolves fleet-cache budgets with fail-closed bounds.
//
// Default mode is off when flag and env are empty. Empty/0 duration or counts at a
// layer mean product default. Negative, unparseable, or out-of-range values error
// (never silent clamp to unsafe).
func ResolveConfig(opts ResolveOptions) (Config, error) {
	getenv := opts.Getenv
	if getenv == nil {
		getenv = os.Getenv
	}

	mode, err := resolveMode(firstNonEmpty(opts.ModeFlag, getenv(EnvMode)))
	if err != nil {
		return Config{}, err
	}

	lookup, err := resolveDuration(
		opts.PeerLookupTimeoutFlag, getenv(EnvPeerLookupTimeout),
		DefaultPeerLookupTimeout, MinPeerLookupTimeout, MaxPeerLookupTimeout,
		EnvPeerLookupTimeout, "--fleet-cache-peer-lookup-timeout",
	)
	if err != nil {
		return Config{}, err
	}

	streams, err := resolveInt(
		opts.MaxPeerStreamsFlag, getenv(EnvMaxPeerStreams),
		DefaultMaxPeerStreams, MinMaxPeerStreams, AbsoluteMaxPeerStreams,
		EnvMaxPeerStreams, "--fleet-cache-max-peer-streams",
	)
	if err != nil {
		return Config{}, err
	}

	lookups, err := resolveInt(
		opts.MaxPeerLookupsFlag, getenv(EnvMaxPeerLookups),
		DefaultMaxPeerLookups, MinMaxPeerLookups, AbsoluteMaxPeerLookups,
		EnvMaxPeerLookups, "--fleet-cache-max-peer-lookups",
	)
	if err != nil {
		return Config{}, err
	}

	// Origin fallback is non-negotiable for availability (ADR 0016).
	// Only accept empty/true/1/yes; explicit false fails closed.
	if raw := strings.TrimSpace(getenv(EnvOriginFallback)); raw != "" {
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			// ok
		case "0", "false", "no", "off":
			return Config{}, apperr.New(apperr.CodeInvalidArgument,
				"fleet-cache origin fallback cannot be disabled ("+EnvOriginFallback+")")
		default:
			return Config{}, apperr.New(apperr.CodeInvalidArgument,
				"invalid "+EnvOriginFallback+" (want true/false)")
		}
	}

	return Config{
		Mode:              mode,
		PeerLookupTimeout: lookup,
		MaxPeerStreams:    streams,
		MaxPeerLookups:    lookups,
		OriginFallback:    true,
	}, nil
}

// Active reports whether any non-off mode is selected (shadow/read/full).
func (c Config) Active() bool {
	return c.Mode != "" && c.Mode != ModeOff
}

// PeerIOEnabled reports whether peer payload I/O is permitted (read or full).
// True still requires mode=read|full and operator wiring; default mode remains off.
func (c Config) PeerIOEnabled() bool {
	return c.Mode == ModeRead || c.Mode == ModeFull
}

// PeerReadHandlersLive is true when owner-directed manifest lookup + bounded
// decoded read library paths exist (FLC-030/031). Default mode remains off;
// near-cache admission is library Done* (FLC-033) with Enabled=false default;
// full multi-node / production GO residual (FLC-073); admin SPA page residual
// (FLC-063 BFF+MCP Done*).
func (c Config) PeerReadHandlersLive() bool {
	return true
}

// StatusSummary is a secret-free operator/status map (FLC-060).
// FLC-061 process-local metrics residual; FLC-062 nests fleet_cache_status (member
// health / doctor inputs). Multi-member *metrics* aggregation remains process-local.
// Admin BFF+MCP fleet-cache ops are FLC-063 Done* (SPA page residual only).
func (c Config) StatusSummary() map[string]any {
	mode := c.Mode
	if mode == "" {
		mode = ModeOff
	}
	// Empty-member status snapshot (callers with roster wire BuildFleetCacheStatus).
	fc := BuildFleetCacheStatus(c, nil, nil, StatusOptions{})
	return map[string]any{
		"mode":                    string(mode),
		"active":                  c.Active(),
		"peer_lookup_timeout":     c.PeerLookupTimeout.String(),
		"max_peer_streams":        c.MaxPeerStreams,
		"max_peer_lookups":        c.MaxPeerLookups,
		"origin_fallback":         c.OriginFallback,
		"peer_read_handlers_live": c.PeerReadHandlersLive(),
		"peer_read_handlers":      "lookup_decoded_read_frame_export", // FLC-022/030/031; FLC-032 coordinator
		// Process-local metrics only (FLC-061); multi-member metrics aggregation residual.
		"aggregation":        MetricsAggregationResidual,
		"fleet_cache_status": fc.Map(), // FLC-062 local vs replica health + residuals
		// Residual honesty: FLC epic library + offline gates Done*; live multi-host / SPA / mTLS residual;
		// object classes default-deny with console_log only (FLC-082); mode default off; HOST-008 cancelled.
		"residual":       "default mode off; FLC epic Done* offline (073 gate pack + 082 class deny); " + ObjectClassStatusResidual() + "; SPA residual; live multi-host residual; mTLS residual; HOST-008 cancelled",
		"object_classes": ObjectClassStatusResidual(),
	}
}

func resolveMode(raw string) (Mode, error) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return ModeOff, nil
	}
	switch Mode(raw) {
	case ModeOff, ModeShadow, ModeRead, ModeFull:
		return Mode(raw), nil
	default:
		return "", apperr.New(apperr.CodeInvalidArgument,
			"invalid fleet-cache mode (want off|shadow|read|full)")
	}
}

func resolveDuration(flagVal, envVal string, def, min, max time.Duration, envName, flagName string) (time.Duration, error) {
	v := def
	if raw := strings.TrimSpace(envVal); raw != "" {
		d, err := parseDurationBudget(raw, "env "+envName, def, min, max)
		if err != nil {
			return 0, err
		}
		v = d
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		d, err := parseDurationBudget(raw, "flag "+flagName, def, min, max)
		if err != nil {
			return 0, err
		}
		v = d
	}
	if v < min || v > max {
		return 0, apperr.New(apperr.CodeInternal, "resolved peer lookup timeout outside absolute bounds")
	}
	return v, nil
}

func parseDurationBudget(raw, src string, def, min, max time.Duration) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		return def, nil
	}
	// Integer milliseconds without unit are accepted for operator simplicity.
	if isAllDigits(raw) {
		ms, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return 0, apperr.New(apperr.CodeInvalidArgument, "invalid "+src+" duration")
		}
		if ms < 0 {
			return 0, apperr.New(apperr.CodeInvalidArgument, src+" duration must not be negative")
		}
		if ms == 0 {
			return def, nil
		}
		d := time.Duration(ms) * time.Millisecond
		if d < min || d > max {
			return 0, apperr.New(apperr.CodeInvalidArgument, src+" duration out of allowed range")
		}
		return d, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument, "invalid "+src+" duration")
	}
	if d < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument, src+" duration must not be negative")
	}
	if d == 0 {
		return def, nil
	}
	if d < min || d > max {
		return 0, apperr.New(apperr.CodeInvalidArgument, src+" duration out of allowed range")
	}
	return d, nil
}

func resolveInt(flagVal, envVal string, def, min, absMax int, envName, flagName string) (int, error) {
	v := def
	if raw := strings.TrimSpace(envVal); raw != "" {
		n, err := parseIntBudget(raw, "env "+envName, def, min, absMax)
		if err != nil {
			return 0, err
		}
		v = n
	}
	if raw := strings.TrimSpace(flagVal); raw != "" {
		n, err := parseIntBudget(raw, "flag "+flagName, def, min, absMax)
		if err != nil {
			return 0, err
		}
		v = n
	}
	if v < min || v > absMax {
		return 0, apperr.New(apperr.CodeInternal, "resolved peer stream/lookup budget outside absolute bounds")
	}
	return v, nil
}

func parseIntBudget(raw, src string, def, min, absMax int) (int, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || raw == "0" {
		return def, nil
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return 0, apperr.New(apperr.CodeInvalidArgument, "invalid "+src+" integer")
	}
	if n < 0 {
		return 0, apperr.New(apperr.CodeInvalidArgument, src+" must not be negative")
	}
	if n == 0 {
		return def, nil
	}
	if n < min || n > absMax {
		return 0, apperr.New(apperr.CodeInvalidArgument, src+" out of allowed range")
	}
	return n, nil
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
