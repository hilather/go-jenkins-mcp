package tools

import (
	"github.com/simonfxr/go-jenkins-mcp/internal/jenkins"
	"github.com/simonfxr/go-jenkins-mcp/internal/telemetry"
)

// JenkinsMetricsHook adapts *telemetry.Metrics to jenkins.MetricsHook (OBS-001).
// Returns nil when m is nil so Client.WithMetrics(nil) clears the hook.
// Counter names are the stable low-cardinality set documented in observability.md;
// no tool names, job names, or secrets are attached.
func JenkinsMetricsHook(m *telemetry.Metrics) jenkins.MetricsHook {
	if m == nil {
		return nil
	}
	return telemetryMetricsHook{m: m}
}

type telemetryMetricsHook struct {
	m *telemetry.Metrics
}

func (h telemetryMetricsHook) AddWire(n int64) {
	if h.m == nil || n <= 0 {
		return
	}
	h.m.AddBytes(telemetry.MetricJenkinsHTTPWireBytesTotal, n)
}

func (h telemetryMetricsHook) AddDecoded(n int64) {
	if h.m == nil || n <= 0 {
		return
	}
	h.m.AddBytes(telemetry.MetricJenkinsHTTPDecodedBytesTotal, n)
}

func (h telemetryMetricsHook) IncRequest() {
	if h.m == nil {
		return
	}
	h.m.Inc(telemetry.MetricJenkinsHTTPRequestsTotal, 1)
}

func (h telemetryMetricsHook) IncError() {
	if h.m == nil {
		return
	}
	h.m.Inc(telemetry.MetricJenkinsHTTPErrorsTotal, 1)
}

func (h telemetryMetricsHook) IncCircuitOpenEvent() {
	if h.m == nil {
		return
	}
	h.m.Inc(telemetry.MetricJenkinsCircuitOpenEventsTotal, 1)
}
