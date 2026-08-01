package telemetry

import (
	"sync"
)

// Core counter / gauge names (low cardinality; OBS-001 / Wave 24).
//
// No free-form tool names, job names, URLs, or secrets as labels — counters
// only. Prefer the *_total / outcome names below in new code; legacy aliases
// keep fleet/doctor snapshots stable where noted.
const (
	// MCP tool dispatch (no per-tool name labels — high cardinality).
	// tool_calls counts every dispatch attempt (ok + error + deny).
	MetricToolCalls    = "tool_calls"
	MetricMCPToolOK    = "mcp_tool_ok"
	MetricMCPToolError = "mcp_tool_error"
	MetricMCPToolDeny  = "mcp_tool_deny"
	// MetricPolicyDenials is a stable alias of mcp_tool_deny (RO / RBAC /
	// session-gate denials at registration or dispatch).
	MetricPolicyDenials = MetricMCPToolDeny

	// Jenkins HTTP transport (wire vs decoded; request/error totals).
	MetricJenkinsHTTPRequestsTotal     = "jenkins_http_requests_total"
	MetricJenkinsHTTPErrorsTotal       = "jenkins_http_errors_total"
	MetricJenkinsHTTPWireBytesTotal    = "jenkins_http_wire_bytes_total"
	MetricJenkinsHTTPDecodedBytesTotal = "jenkins_http_decoded_bytes_total"
	// NET-003 circuit breaker (OBS Wave 27): open transitions only (low cardinality).
	// Current state is doctor/status via Client.CircuitState(), not a label series.
	MetricJenkinsCircuitOpenEventsTotal = "jenkins_circuit_open_events_total"
	// Legacy aliases (same values as MetricJenkinsHTTP*).
	MetricJenkinsRequests = MetricJenkinsHTTPRequestsTotal
	MetricBytesWire       = MetricJenkinsHTTPWireBytesTotal

	MetricCacheHits      = "cache_hits"
	MetricMCPBytesOut    = "mcp_bytes_out"
	MetricDuplicateBytes = "duplicate_bytes_avoided"
	// Cache maintenance (ARC-007 / ARC-005 residual; no secret labels).
	MetricCacheMaintTicks     = "cache_maint_ticks"
	MetricCacheEvictItems     = "cache_evict_items"
	MetricCacheEvictBytes     = "cache_evict_bytes_reclaimed"
	MetricCachePacksCreated   = "cache_packs_created"
	MetricCacheL1Released     = "cache_l1_released"
	MetricCacheL1ReleaseBytes = "cache_l1_release_bytes_reclaimed"
	MetricCacheUsageBytes     = "cache_usage_bytes"
	MetricCacheQuotaBytes     = "cache_quota_bytes"
)

// Metrics is an in-process counter/gauge registry (thread-safe).
type Metrics struct {
	mu       sync.Mutex
	counters map[string]int64
	gauges   map[string]int64
}

// NewMetrics returns an empty metrics bag.
func NewMetrics() *Metrics {
	return &Metrics{
		counters: make(map[string]int64),
		gauges:   make(map[string]int64),
	}
}

// Inc adds delta (default 1 when delta==0 is not special — pass 1 explicitly)
// to a counter. Negative deltas are ignored (counters only go up).
func (m *Metrics) Inc(name string, delta int64) {
	if m == nil || name == "" || delta <= 0 {
		return
	}
	m.mu.Lock()
	m.counters[name] += delta
	m.mu.Unlock()
}

// AddBytes increments a byte counter (jenkins_http_wire_bytes_total, mcp_bytes_out, …).
func (m *Metrics) AddBytes(name string, n int64) {
	m.Inc(name, n)
}

// SetGauge stores the latest gauge value (may go down).
func (m *Metrics) SetGauge(name string, v int64) {
	if m == nil || name == "" {
		return
	}
	m.mu.Lock()
	m.gauges[name] = v
	m.mu.Unlock()
}

// GetCounter returns the current counter value.
func (m *Metrics) GetCounter(name string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.counters[name]
}

// GetGauge returns the current gauge value.
func (m *Metrics) GetGauge(name string) int64 {
	if m == nil {
		return 0
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.gauges[name]
}

// Snapshot is a point-in-time copy of counters and gauges.
type Snapshot struct {
	Counters map[string]int64 `json:"counters"`
	Gauges   map[string]int64 `json:"gauges"`
}

// Snapshot returns a deep copy of current values for doctor/status later.
func (m *Metrics) Snapshot() Snapshot {
	out := Snapshot{
		Counters: make(map[string]int64),
		Gauges:   make(map[string]int64),
	}
	if m == nil {
		return out
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for k, v := range m.counters {
		out.Counters[k] = v
	}
	for k, v := range m.gauges {
		out.Gauges[k] = v
	}
	return out
}
