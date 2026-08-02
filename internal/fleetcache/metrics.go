package fleetcache

import (
	"context"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/hilather/go-jenkins-mcp/internal/redact"
)

// Process-local fleet-cache metrics (FLC-061).
//
// Counters are low-cardinality names only — never member IDs, job names, URLs,
// tokens, or free-form labels. Multi-member aggregation is residual (FLC-062+).

// Stable counter names (no labels).
const (
	MetricPeerHit           = "peer_hit"
	MetricLocalHit          = "local_hit"
	MetricOriginFill        = "origin_fill"
	MetricOriginBytes       = "origin_bytes"
	MetricPeerBytesWire     = "peer_bytes_wire"
	MetricPeerBytesDecoded  = "peer_bytes_decoded"
	MetricMCPBytesOut       = "mcp_bytes_out"
	MetricLocalHitDecoded   = "local_hit_decoded_bytes"
	MetricPeerHitDecoded    = "peer_hit_decoded_bytes"
	MetricLeaseProducer     = "lease_producer"
	MetricLeaseWaiter       = "lease_waiter"
	MetricImportCommitted   = "import_committed"
	MetricImportIdempotent  = "import_idempotent"
	MetricImportRejected    = "import_rejected"
	MetricReplicateFrames   = "replicate_frames"
	MetricRepairCopies      = "repair_copies"
	MetricAuthzDeny         = "authz_deny"
	MetricAuthzOK           = "authz_ok"
	MetricCorruptReject     = "corrupt_reject"
	MetricFallbackOrigin    = "fallback_origin"
	MetricRFUnderReplicated = "rf_under_replicated"
	// Gauge-ish snapshot fields (set via RFHealth).
	MetricRFRequired = "rf_required"
	MetricRFHealthy  = "rf_healthy"
	// Computed snapshot field (local_hit_decoded_bytes + peer_hit_decoded_bytes).
	MetricOriginBytesAvoided = "origin_bytes_avoided"
	// Near-cache admission (FLC-033); low-cardinality only.
	MetricNearAdmit = "near_admit"
	MetricNearDeny  = "near_deny"
)

// MetricsAggregationResidual is the honest multi-member aggregation residual (FLC-061/062).
const MetricsAggregationResidual = "process_local_only; multi_member residual FLC-062+"

// Security event type strings (low-cardinality, secret-free).
const (
	SecurityTypeAuthzDeny      = "fleet_cache_authz_deny"
	SecurityTypeImportConflict = "fleet_cache_import_conflict"
	SecurityTypeCorrupt        = "fleet_cache_corrupt"
	SecurityTypeFallback       = "fleet_cache_fallback"
)

// securityEventCap bounds the in-process ring of recent security events.
const securityEventCap = 64

// knownMetricNames is the stable dictionary returned by Snapshot (zeros included).
var knownMetricNames = []string{
	MetricPeerHit,
	MetricLocalHit,
	MetricOriginFill,
	MetricOriginBytes,
	MetricPeerBytesWire,
	MetricPeerBytesDecoded,
	MetricMCPBytesOut,
	MetricLocalHitDecoded,
	MetricPeerHitDecoded,
	MetricLeaseProducer,
	MetricLeaseWaiter,
	MetricImportCommitted,
	MetricImportIdempotent,
	MetricImportRejected,
	MetricReplicateFrames,
	MetricRepairCopies,
	MetricAuthzDeny,
	MetricAuthzOK,
	MetricCorruptReject,
	MetricFallbackOrigin,
	MetricRFUnderReplicated,
	MetricRFRequired,
	MetricRFHealthy,
	MetricOriginBytesAvoided,
	MetricNearAdmit,
	MetricNearDeny,
}

// SecurityEvent is a process-local, secret-free security residual (FLC-061).
// Not a full AUD-001 sink wire — doctor/admin aggregation is FLC-062+.
type SecurityEvent struct {
	Type              string // fleet_cache_authz_deny | fleet_cache_import_conflict | fleet_cache_corrupt | fleet_cache_fallback
	ReasonCode        string
	LocatorHashPrefix string // first 12 hex of locator hash (or shorter); never job name free text
	Residual          string // scrubbed; never tokens, passwords, Authorization, raw logs, credentialed URLs
}

// FleetCacheMetrics is a process-local registry (FLC-061). Not multi-member aggregation.
type FleetCacheMetrics struct {
	counters sync.Map // string -> *atomic.Int64

	rfRequired atomic.Int64
	rfHealthy  atomic.Int64

	secMu   sync.Mutex
	secRing []SecurityEvent
	secNext int
	secFull bool
}

// Metrics is the package-level process-local registry. Prefer ResetForTest in tests.
var Metrics = DefaultMetrics()

// DefaultMetrics returns a new empty process-local metrics bag.
func DefaultMetrics() *FleetCacheMetrics {
	return &FleetCacheMetrics{}
}

// ResetForTest clears the package Metrics bag in place (tests only; not concurrent-safe
// with parallel tests that also call ResetForTest).
func ResetForTest() {
	if Metrics == nil {
		Metrics = DefaultMetrics()
		return
	}
	Metrics.Reset()
}

// Reset clears this instance (useful when tests inject a private bag).
func (m *FleetCacheMetrics) Reset() {
	if m == nil {
		return
	}
	m.counters.Range(func(k, _ any) bool {
		m.counters.Delete(k)
		return true
	})
	m.rfRequired.Store(0)
	m.rfHealthy.Store(0)
	m.secMu.Lock()
	m.secRing = nil
	m.secNext = 0
	m.secFull = false
	m.secMu.Unlock()
}

// Inc adds delta to a named counter. Unknown names are accepted but Snapshot only
// guarantees the known dictionary. Negative or zero deltas are ignored.
func (m *FleetCacheMetrics) Inc(name string, delta int64) {
	if m == nil || name == "" || delta <= 0 {
		return
	}
	v, _ := m.counters.LoadOrStore(name, &atomic.Int64{})
	v.(*atomic.Int64).Add(delta)
}

// AddBytes increments a byte counter by kind: origin | wire | decoded | mcp.
func (m *FleetCacheMetrics) AddBytes(kind string, n int64) {
	if m == nil || n <= 0 {
		return
	}
	switch strings.ToLower(strings.TrimSpace(kind)) {
	case "origin":
		m.Inc(MetricOriginBytes, n)
	case "wire":
		m.Inc(MetricPeerBytesWire, n)
	case "decoded":
		m.Inc(MetricPeerBytesDecoded, n)
	case "mcp":
		m.Inc(MetricMCPBytesOut, n)
	}
}

func (m *FleetCacheMetrics) getCounter(name string) int64 {
	if m == nil {
		return 0
	}
	v, ok := m.counters.Load(name)
	if !ok {
		return 0
	}
	return v.(*atomic.Int64).Load()
}

// Snapshot returns a secret-free map of known counters/gauges (zeros included).
// Process-local only — see MetricsAggregationResidual / StatusSummary "aggregation".
func (m *FleetCacheMetrics) Snapshot() map[string]int64 {
	out := make(map[string]int64, len(knownMetricNames))
	for _, name := range knownMetricNames {
		switch name {
		case MetricRFRequired:
			if m != nil {
				out[name] = m.rfRequired.Load()
			}
		case MetricRFHealthy:
			if m != nil {
				out[name] = m.rfHealthy.Load()
			}
		case MetricOriginBytesAvoided:
			out[name] = m.OriginBytesAvoided()
		default:
			out[name] = m.getCounter(name)
		}
	}
	return out
}

// OriginBytesAvoided is local_hit_decoded_bytes + peer_hit_decoded_bytes (explicit).
func (m *FleetCacheMetrics) OriginBytesAvoided() int64 {
	if m == nil {
		return 0
	}
	return m.getCounter(MetricLocalHitDecoded) + m.getCounter(MetricPeerHitDecoded)
}

// RFHealth records required vs healthy replica counts and returns under-replicated.
// Snapshot fields: rf_required, rf_healthy; increments rf_under_replicated when unhealthy.
func (m *FleetCacheMetrics) RFHealth(required, healthy int) (underReplicated bool) {
	if m == nil {
		return healthy < required
	}
	if required < 0 {
		required = 0
	}
	if healthy < 0 {
		healthy = 0
	}
	m.rfRequired.Store(int64(required))
	m.rfHealthy.Store(int64(healthy))
	underReplicated = healthy < required
	if underReplicated {
		m.Inc(MetricRFUnderReplicated, 1)
	}
	return underReplicated
}

// AggregationResidual returns the multi-member aggregation residual string.
func (m *FleetCacheMetrics) AggregationResidual() string {
	return MetricsAggregationResidual
}

// --- Record helpers (public; used by callers and thin facades) ---

// RecordLookupOutcome records a local|peer|origin resolution with decoded byte savings.
// source is low-cardinality: "local" | "peer" | "origin".
func (m *FleetCacheMetrics) RecordLookupOutcome(source string, decodedBytes int64) {
	if m == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "local":
		m.Inc(MetricLocalHit, 1)
		if decodedBytes > 0 {
			m.Inc(MetricLocalHitDecoded, decodedBytes)
		}
	case "peer":
		m.Inc(MetricPeerHit, 1)
		if decodedBytes > 0 {
			m.Inc(MetricPeerHitDecoded, decodedBytes)
			m.AddBytes("decoded", decodedBytes)
		}
	case "origin":
		m.Inc(MetricOriginFill, 1)
		if decodedBytes > 0 {
			m.AddBytes("origin", decodedBytes)
		}
	}
}

// RecordImportResult records import/replicate status and frame transfer count.
// status: committed | idempotent | rejected | aborted (others ignored for counters).
func (m *FleetCacheMetrics) RecordImportResult(status string, frames int) {
	if m == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(status)) {
	case ImportStatusCommitted:
		m.Inc(MetricImportCommitted, 1)
		if frames > 0 {
			m.Inc(MetricReplicateFrames, int64(frames))
		}
	case ImportStatusIdempotent:
		m.Inc(MetricImportIdempotent, 1)
	case ImportStatusRejected:
		m.Inc(MetricImportRejected, 1)
	}
}

// ObserveReplicateResult updates counters from a ReplicateSealed/Wave result and
// emits security residuals for conflict/corrupt rejects.
func (m *FleetCacheMetrics) ObserveReplicateResult(res ReplicateResult) {
	if m == nil {
		return
	}
	m.RecordImportResult(res.Status, res.FramesTransferred)
	residual := res.Residual
	switch {
	case res.Status == ImportStatusRejected && residual == PartitionResidualConflictDigest:
		m.EmitSecurity(SecurityEvent{
			Type:              SecurityTypeImportConflict,
			ReasonCode:        residual,
			LocatorHashPrefix: locatorHashPrefix(res.LocatorHash),
			Residual:          residual,
		})
	case res.Status == ImportStatusRejected && (strings.Contains(residual, "corrupt") || residual == "frame validation failed"):
		m.Inc(MetricCorruptReject, 1)
		m.EmitSecurity(SecurityEvent{
			Type:              SecurityTypeCorrupt,
			ReasonCode:        "corrupt_or_invalid_frame",
			LocatorHashPrefix: locatorHashPrefix(res.LocatorHash),
			Residual:          residual,
		})
	case res.Status == ImportStatusRejected:
		// Generic reject still visible as import_rejected; no extra event unless residual set.
	}
}

// RecordAuthzDecision records allow/deny and emits a security event on deny.
func (m *FleetCacheMetrics) RecordAuthzDecision(dec AuthzDecision) {
	if m == nil {
		return
	}
	if dec.Allowed {
		m.Inc(MetricAuthzOK, 1)
		return
	}
	m.Inc(MetricAuthzDeny, 1)
	rc := dec.ReasonCode
	if rc == "" {
		rc = ReasonAuthzPolicyDeny
	}
	m.EmitSecurity(SecurityEvent{
		Type:       SecurityTypeAuthzDeny,
		ReasonCode: rc,
		Residual:   rc,
	})
}

// RecordFallbackOrigin increments fallback_origin and emits a security residual.
func (m *FleetCacheMetrics) RecordFallbackOrigin(reasonCode string) {
	if m == nil {
		return
	}
	m.Inc(MetricFallbackOrigin, 1)
	if reasonCode == "" {
		reasonCode = "origin_fallback"
	}
	m.EmitSecurity(SecurityEvent{
		Type:       SecurityTypeFallback,
		ReasonCode: reasonCode,
		Residual:   reasonCode,
	})
}

// RecordLeaseRole increments lease_producer or lease_waiter ("producer"|"waiter").
func (m *FleetCacheMetrics) RecordLeaseRole(role string) {
	if m == nil {
		return
	}
	switch strings.ToLower(strings.TrimSpace(role)) {
	case "producer":
		m.Inc(MetricLeaseProducer, 1)
	case "waiter":
		m.Inc(MetricLeaseWaiter, 1)
	}
}

// RecordRepairCopies increments repair_copies by n.
func (m *FleetCacheMetrics) RecordRepairCopies(n int) {
	if m == nil || n <= 0 {
		return
	}
	m.Inc(MetricRepairCopies, int64(n))
}

// RecordNearAdmit increments near_admit or near_deny from an AdmitNearCache result (FLC-033).
// Residual codes are not stored on the counter (low-cardinality name only).
func (m *FleetCacheMetrics) RecordNearAdmit(result NearAdmitResult) {
	if m == nil {
		return
	}
	if result.Admit {
		m.Inc(MetricNearAdmit, 1)
		return
	}
	m.Inc(MetricNearDeny, 1)
}

// --- Package-level facades (use Metrics) ---

// RecordLookupOutcome records against the package Metrics registry.
func RecordLookupOutcome(source string, decodedBytes int64) {
	Metrics.RecordLookupOutcome(source, decodedBytes)
}

// RecordImportResult records against the package Metrics registry.
func RecordImportResult(status string, frames int) {
	Metrics.RecordImportResult(status, frames)
}

// ObserveReplicateResult records against the package Metrics registry.
func ObserveReplicateResult(res ReplicateResult) {
	Metrics.ObserveReplicateResult(res)
}

// RecordAuthzDecision records against the package Metrics registry.
func RecordAuthzDecision(dec AuthzDecision) {
	Metrics.RecordAuthzDecision(dec)
}

// RecordNearAdmit records against the package Metrics registry (FLC-033).
func RecordNearAdmit(result NearAdmitResult) {
	Metrics.RecordNearAdmit(result)
}

// ReplicateSealedObserved runs ReplicateSealed then ObserveReplicateResult (FLC-061).
// Prefer this over bare ReplicateSealed when process-local import/replica counters are desired.
func ReplicateSealedObserved(ctx context.Context, sink ImportSink, m WireManifest, frames []ImportFrameBytes) (ReplicateResult, error) {
	res, err := ReplicateSealed(ctx, sink, m, frames)
	ObserveReplicateResult(res)
	return res, err
}

// EmitSecurity appends a scrubbed security event to the bounded ring.
func (m *FleetCacheMetrics) EmitSecurity(ev SecurityEvent) {
	if m == nil {
		return
	}
	ev = scrubSecurityEvent(ev)
	m.secMu.Lock()
	defer m.secMu.Unlock()
	if len(m.secRing) < securityEventCap {
		// Grow until cap, then ring.
		if cap(m.secRing) < securityEventCap {
			m.secRing = make([]SecurityEvent, 0, securityEventCap)
		}
		m.secRing = append(m.secRing, ev)
		if len(m.secRing) == securityEventCap {
			m.secFull = true
			m.secNext = 0
		}
		return
	}
	m.secRing[m.secNext] = ev
	m.secNext = (m.secNext + 1) % securityEventCap
	m.secFull = true
}

// RecentSecurity returns up to max recent security events (oldest→newest within window).
func (m *FleetCacheMetrics) RecentSecurity(max int) []SecurityEvent {
	if m == nil || max <= 0 {
		return nil
	}
	m.secMu.Lock()
	defer m.secMu.Unlock()
	n := len(m.secRing)
	if n == 0 {
		return nil
	}
	var ordered []SecurityEvent
	if !m.secFull {
		ordered = append([]SecurityEvent(nil), m.secRing...)
	} else {
		ordered = make([]SecurityEvent, 0, n)
		for i := 0; i < n; i++ {
			idx := (m.secNext + i) % n
			ordered = append(ordered, m.secRing[idx])
		}
	}
	if max < len(ordered) {
		ordered = ordered[len(ordered)-max:]
	}
	// Defensive copy of residual strings already scrubbed; still re-scrub on read.
	out := make([]SecurityEvent, len(ordered))
	for i := range ordered {
		out[i] = scrubSecurityEvent(ordered[i])
	}
	return out
}

func locatorHashPrefix(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	// Keep hex-ish only; never free-form job names.
	var b strings.Builder
	for _, r := range h {
		if (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') {
			b.WriteRune(r)
		}
	}
	s := b.String()
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

// token/Bearer canaries beyond redact package (fail-closed scrub to [redacted]).
var (
	tokenEqRE  = regexp.MustCompile(`(?i)\btoken\s*[=:]\s*\S+`)
	bearerRE   = regexp.MustCompile(`(?i)\bbearer\s+\S+`)
	passwordRE = regexp.MustCompile(`(?i)\bpassword\s*[=:]\s*\S+`)
	// Credentialed URL user:pass@
	credURLRE = regexp.MustCompile(`(?i)(https?://)[^/\s:@]+:[^/\s@]+@`)
)

const scrubMarker = "[redacted]"

func scrubSecretFree(s string) string {
	if s == "" {
		return s
	}
	// Layer 1: enterprise redact package ([REDACTED] marker).
	out := redact.RedactText(s)
	// Layer 2: strip secret-shaped spans entirely (no leftover "token=" / "Bearer " keywords
	// that would trip secret canaries). Marker only.
	out = tokenEqRE.ReplaceAllString(out, scrubMarker)
	out = bearerRE.ReplaceAllString(out, scrubMarker)
	out = passwordRE.ReplaceAllString(out, scrubMarker)
	out = credURLRE.ReplaceAllString(out, "${1}"+scrubMarker+"@")
	// Fail-closed: if residual secret shapes remain, blank residual.
	if stillSecretShaped(out) {
		return scrubMarker
	}
	return out
}

func stillSecretShaped(s string) bool {
	// Any remaining token=/Bearer <value>/password= shapes are fail-closed.
	if tokenEqRE.MatchString(s) || bearerRE.MatchString(s) || passwordRE.MatchString(s) {
		return true
	}
	if strings.Contains(s, "://") && strings.Contains(s, "@") && credURLRE.MatchString(s) {
		return true
	}
	return false
}

func scrubSecurityEvent(ev SecurityEvent) SecurityEvent {
	ev.Type = scrubSecretFree(ev.Type)
	ev.ReasonCode = scrubSecretFree(ev.ReasonCode)
	ev.LocatorHashPrefix = locatorHashPrefix(ev.LocatorHashPrefix)
	ev.Residual = scrubSecretFree(ev.Residual)
	// Cap residual length (no raw log bodies).
	const maxResidual = 256
	if len(ev.Residual) > maxResidual {
		ev.Residual = ev.Residual[:maxResidual]
	}
	return ev
}
