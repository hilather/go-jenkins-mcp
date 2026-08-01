package otelx

// Well-known Jenkins parameter / env-style keys scanned for correlation IDs.
// Matching is case-insensitive; hyphens are normalized to underscores.
//
// Documented allowlist (INT-002 MVP):
//
//	TRACEPARENT                 W3C trace context header value
//	TRACE_ID, TRACEID           32-hex OpenTelemetry / W3C trace id
//	OTEL_TRACE_ID               same
//	SPAN_ID, SPANID             16-hex span id
//	OTEL_SPAN_ID                same
//	SERVICE_NAME                service name label
//	OTEL_SERVICE_NAME           same
//	OTEL_SERVICE                same
//	OTEL_RESOURCE_ATTRIBUTES    parse service.name= from resource attrs
//	dd.trace_id, DD_TRACE_ID    Datadog trace id (decimal or hex)
//	dd.span_id, DD_SPAN_ID      Datadog span id
//
// Values from sensitive-looking parameter names (password, token, secret, …)
// are never read. Values that fail format validation are dropped so arbitrary
// secrets cannot leak through misnamed keys.
//
// Residual keys (not extracted in MVP): baggage, tracestate, full OTEL
// resource maps beyond service.name, custom vendor headers beyond Datadog.
const (
	KeyTraceparent            = "TRACEPARENT"
	KeyTraceID                = "TRACE_ID"
	KeyTraceIDCompact         = "TRACEID"
	KeyOTELTraceID            = "OTEL_TRACE_ID"
	KeySpanID                 = "SPAN_ID"
	KeySpanIDCompact          = "SPANID"
	KeyOTELSpanID             = "OTEL_SPAN_ID"
	KeyServiceName            = "SERVICE_NAME"
	KeyOTELServiceName        = "OTEL_SERVICE_NAME"
	KeyOTELService            = "OTEL_SERVICE"
	KeyOTELResourceAttributes = "OTEL_RESOURCE_ATTRIBUTES"
	KeyDDTraceID              = "DD_TRACE_ID"
	KeyDDTraceIDDot           = "DD.TRACE_ID" // after normalize: dd_trace_id
	KeyDDSpanID               = "DD_SPAN_ID"
	KeyDDSpanIDDot            = "DD.SPAN_ID"
)

// EvidenceSourceBuildMetadata labels refs that came only from Jenkins build
// parameters/actions (no external backend round-trip).
const EvidenceSourceBuildMetadata = "jenkins_build_metadata"

// Format labels for TraceRef.Format.
const (
	FormatW3CTraceparent = "w3c_traceparent"
	FormatHexTraceID     = "hex_trace_id"
	FormatHexSpanID      = "hex_span_id"
	FormatDatadogTraceID = "datadog_trace_id"
	FormatDatadogSpanID  = "datadog_span_id"
	FormatServiceName    = "service_name"
	FormatOTELResource   = "otel_resource_attributes"
)

// Source labels for TraceRef.Source.
const (
	SourceBuildParameter = "build_parameter"
)
