package jenkins

// MetricsHook records low-cardinality Jenkins HTTP metrics (OBS-001 / Wave 24–27).
//
// Implemented outside this package (e.g. internal/tools or cmd) so jenkins does
// not import internal/telemetry (FND-004 depgraph). Implementations must be
// safe for concurrent use and must not retain body content, URLs with secrets,
// Authorization headers, or free-form high-cardinality labels.
//
// Typical counters (wired by the adapter):
//   - AddWire / AddDecoded → jenkins_http_wire_bytes_total / jenkins_http_decoded_bytes_total
//   - IncRequest → jenkins_http_requests_total
//   - IncError → jenkins_http_errors_total (transport failure or HTTP status ≥ 400)
//   - IncCircuitOpenEvent → jenkins_circuit_open_events_total (NET-003 breaker open)
//
// Current circuit state is exposed via Client.CircuitState() for doctor/status
// (not a high-cardinality label series).
type MetricsHook interface {
	AddWire(n int64)
	AddDecoded(n int64)
	IncRequest()
	IncError()
	// IncCircuitOpenEvent records a transition into the open circuit state.
	// Called at most once per open episode (not while already open).
	IncCircuitOpenEvent()
}

// metricsHookByteCounters adapts MetricsHook to ByteCounters for wrapResponseBody.
type metricsHookByteCounters struct {
	h MetricsHook
}

func (c metricsHookByteCounters) AddWireBytes(n int64) {
	if c.h != nil && n > 0 {
		c.h.AddWire(n)
	}
}

func (c metricsHookByteCounters) AddDecodedBytes(n int64) {
	if c.h != nil && n > 0 {
		c.h.AddDecoded(n)
	}
}

// fanoutByteCounters fans wire/decoded counts to two sinks (explicit ByteCounters
// plus MetricsHook) without retaining body bytes.
type fanoutByteCounters struct {
	a, b ByteCounters
}

func (f fanoutByteCounters) AddWireBytes(n int64) {
	if f.a != nil {
		f.a.AddWireBytes(n)
	}
	if f.b != nil {
		f.b.AddWireBytes(n)
	}
}

func (f fanoutByteCounters) AddDecodedBytes(n int64) {
	if f.a != nil {
		f.a.AddDecodedBytes(n)
	}
	if f.b != nil {
		f.b.AddDecodedBytes(n)
	}
}

// isNopByteCounters reports whether c is nil or the typed NopByteCounters.
func isNopByteCounters(c ByteCounters) bool {
	if c == nil {
		return true
	}
	_, ok := c.(NopByteCounters)
	return ok
}
