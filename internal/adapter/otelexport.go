package adapter

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"unicode"
)

// INT-002 built-in adapter ID: OTLP export framework stub (metadata-only envelopes).
// No production OTLP/OTLP-HTTP protobuf collector client; backends are noop, mock,
// or optional HTTPS JSON metadata POST.
const IDOtelExport = "otel-export"

// OtelExportBackendName selects the export backend for the otel-export adapter.
type OtelExportBackendName string

const (
	// OtelExportBackendNoop records nothing and performs no network I/O (default).
	OtelExportBackendNoop OtelExportBackendName = "noop"
	// OtelExportBackendMock records in-memory export attempts for tests.
	OtelExportBackendMock OtelExportBackendName = "mock"
	// OtelExportBackendHTTP POSTs allowlisted JSON envelopes to an HTTPS origin.
	OtelExportBackendHTTP OtelExportBackendName = "http"
)

// Bounds for metadata-only export (INT-002 export stub).
const (
	// DefaultMaxExportEnvelopes is the default cap on envelopes per export call.
	DefaultMaxExportEnvelopes = 8
	// HardMaxExportEnvelopes is the absolute ceiling.
	HardMaxExportEnvelopes = 16
	// MaxExportTraceIDLen is the max accepted trace_id length (hex chars).
	MaxExportTraceIDLen = 64
	// MaxExportSpanIDLen is the max accepted span_id length (hex chars).
	MaxExportSpanIDLen = 32
	// MaxExportServiceLen bounds service labels.
	MaxExportServiceLen = 128
	// MaxExportJobLen bounds job path strings.
	MaxExportJobLen = 512
	// MaxExportFormatLen bounds format labels (e.g. w3c_traceparent).
	MaxExportFormatLen = 64
	// EvidenceSourceOtelExport labels export-attempt evidence (not remote query).
	EvidenceSourceOtelExport = "otel_export_stub"
)

// residualOtelExportClient is returned so operators know real OTLP clients remain open.
const residualOtelExportClient = "real OTLP/OTLP-HTTP protobuf collector client residual (INT-002 MVP: noop/mock/optional HTTPS JSON metadata stub only; no log text)"

// TraceExportEnvelope is a metadata-only correlation envelope for export.
// Allowlisted fields only — never console logs, tokens, or full parameter maps.
type TraceExportEnvelope struct {
	// TraceID is a validated hex-ish correlation id (optional if Service present).
	TraceID string `json:"trace_id,omitempty"`
	// SpanID is an optional validated span id.
	SpanID string `json:"span_id,omitempty"`
	// Service is a short service label when known.
	Service string `json:"service,omitempty"`
	// Job is the Jenkins job full name (folder/job path).
	Job string `json:"job"`
	// Build is the Jenkins build number.
	Build int `json:"build"`
	// Format classifies the identifier encoding when known (e.g. w3c_traceparent).
	Format string `json:"format,omitempty"`
}

// TraceExportRequest is a bounded export attempt keyed by job/build identity.
type TraceExportRequest struct {
	// Job is the Jenkins job full name (folder/job path).
	Job string
	// Build is the Jenkins build number.
	Build int
	// Envelopes are allowlisted metadata envelopes (caller must not include log text).
	Envelopes []TraceExportEnvelope
}

// TraceExportResult is the export attempt outcome (status + residual; no secrets).
type TraceExportResult struct {
	// Status is a short outcome label: noop | recorded | exported | empty.
	Status string `json:"status"`
	// Backend is the backend name (noop|mock|http).
	Backend string `json:"backend"`
	// Accepted is the number of envelopes accepted after allowlist/normalize.
	Accepted int `json:"accepted"`
	// Attempted is the number of envelopes the caller submitted (pre-filter).
	Attempted int `json:"attempted"`
	// Truncated when more envelopes existed than the hard cap.
	Truncated bool `json:"truncated,omitempty"`
	// EvidenceSource labels this path.
	EvidenceSource string `json:"evidence_source"`
	// Residuals document missing real OTLP clients / limits.
	Residuals []string `json:"residuals,omitempty"`
	// Message is a short status string (never secrets).
	Message string `json:"message,omitempty"`
}

// TraceExporter is the capability surface for otel-export backends.
// Implemented by OtelExport (and tests). Does not receive Jenkins credentials.
type TraceExporter interface {
	ExportTraceRefs(ctx context.Context, req TraceExportRequest) (TraceExportResult, error)
}

// OtelExportConfig configures the otel-export adapter factory (paths only; no secrets).
type OtelExportConfig struct {
	// Backend selects noop|mock|http (default noop).
	Backend OtelExportBackendName
	// BaseURL is the allowlisted HTTPS origin for the http backend (required for http).
	// Paths and origin only — credentials are residual (keyring namespace).
	BaseURL string
	// HTTP is optional for tests; nil uses a timeout client for production http.
	// Never inject a client that carries Jenkins credentials.
	HTTP HTTPDoer
}

// OtelExport is the INT-002 export framework stub (lifecycle + TraceExporter).
type OtelExport struct {
	host    Host
	cfg     OtelExportConfig
	backend exportBackend

	mu      sync.Mutex
	started bool
	stopped bool
}

// OtelExportFactory returns a Factory that builds OtelExport with the given config.
func OtelExportFactory(cfg OtelExportConfig) Factory {
	return func(host Host) (Adapter, error) {
		return NewOtelExport(host, cfg)
	}
}

// NewOtelExport constructs the otel-export adapter. Backend defaults to noop.
func NewOtelExport(host Host, cfg OtelExportConfig) (Adapter, error) {
	cfg = normalizeOtelExportConfig(cfg)
	backend, err := newExportBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &OtelExport{host: host, cfg: cfg, backend: backend}, nil
}

// NewOtelExportDefault is the DefaultCatalog factory (noop backend; no network).
func NewOtelExportDefault(host Host) (Adapter, error) {
	return NewOtelExport(host, OtelExportConfig{Backend: OtelExportBackendNoop})
}

func normalizeOtelExportConfig(cfg OtelExportConfig) OtelExportConfig {
	switch strings.ToLower(strings.TrimSpace(string(cfg.Backend))) {
	case "", string(OtelExportBackendNoop):
		cfg.Backend = OtelExportBackendNoop
	case string(OtelExportBackendMock):
		cfg.Backend = OtelExportBackendMock
	case string(OtelExportBackendHTTP):
		cfg.Backend = OtelExportBackendHTTP
	default:
		cfg.Backend = OtelExportBackendName(strings.ToLower(strings.TrimSpace(string(cfg.Backend))))
	}
	return cfg
}

func newExportBackend(cfg OtelExportConfig) (exportBackend, error) {
	switch cfg.Backend {
	case OtelExportBackendNoop:
		return &noopExportBackend{}, nil
	case OtelExportBackendMock:
		return &mockExportBackend{}, nil
	case OtelExportBackendHTTP:
		return newHTTPExportBackend(cfg)
	default:
		return nil, fmt.Errorf("unknown otel-export backend %q (want noop|mock|http)", cfg.Backend)
	}
}

func (o *OtelExport) ID() string { return IDOtelExport }

func (o *OtelExport) Capabilities() []Capability {
	return []Capability{CapLifecycle, CapOtelExport}
}

func (o *OtelExport) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	o.mu.Lock()
	o.started = true
	o.stopped = false
	o.mu.Unlock()
	o.host.logf("adapter otel-export: started backend=%s (metadata-only; no OTLP protobuf; no log text)", o.cfg.Backend)
	return nil
}

func (o *OtelExport) Stop(ctx context.Context) error {
	_ = ctx
	o.mu.Lock()
	o.stopped = true
	o.started = false
	o.mu.Unlock()
	o.host.logf("adapter otel-export: stopped")
	return nil
}

func (o *OtelExport) Health(ctx context.Context) Health {
	_ = ctx
	o.mu.Lock()
	defer o.mu.Unlock()
	switch {
	case o.stopped && !o.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: o.host.now()}
	case o.started:
		return Health{
			Status:    HealthHealthy,
			Message:   fmt.Sprintf("otel export stub enabled (backend=%s; metadata envelopes only; no log text)", o.cfg.Backend),
			CheckedAt: o.host.now(),
		}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: o.host.now()}
	}
}

// ExportTraceRefs implements TraceExporter with allowlist normalize + start gate.
// Callers should use adapter.Call for panic isolation + rate limit.
func (o *OtelExport) ExportTraceRefs(ctx context.Context, req TraceExportRequest) (TraceExportResult, error) {
	if err := ctx.Err(); err != nil {
		return TraceExportResult{}, err
	}
	o.mu.Lock()
	started := o.started
	o.mu.Unlock()
	if !started {
		return TraceExportResult{}, fmt.Errorf("adapter %q is not started", IDOtelExport)
	}
	norm, truncated, err := normalizeExportRequest(req)
	if err != nil {
		return TraceExportResult{}, err
	}
	res, err := o.backend.Export(ctx, norm)
	if err != nil {
		return TraceExportResult{}, err
	}
	res = finalizeExportResult(res, norm, truncated, string(o.cfg.Backend))
	return res, nil
}

// RecordedExports returns in-memory export attempts when backend is mock.
// Returns nil for noop/http. Intended for tests.
func (o *OtelExport) RecordedExports() []TraceExportRequest {
	if m, ok := o.backend.(*mockExportBackend); ok {
		return m.snapshot()
	}
	return nil
}

// exportBackend is the pluggable engine behind OtelExport.
type exportBackend interface {
	Export(ctx context.Context, req TraceExportRequest) (TraceExportResult, error)
}

// normalizeExportRequest validates identity and allowlists envelope fields.
// Never passes through log text, tokens, or full parameter maps (not in struct).
func normalizeExportRequest(req TraceExportRequest) (TraceExportRequest, bool, error) {
	req.Job = strings.TrimSpace(req.Job)
	if req.Job == "" {
		return TraceExportRequest{}, false, fmt.Errorf("job is required")
	}
	if strings.Contains(req.Job, "://") {
		return TraceExportRequest{}, false, fmt.Errorf("job must be a typed path, not a URL")
	}
	if utf8Len(req.Job) > MaxExportJobLen {
		return TraceExportRequest{}, false, fmt.Errorf("job exceeds max length %d", MaxExportJobLen)
	}
	if req.Build <= 0 {
		return TraceExportRequest{}, false, fmt.Errorf("build must be positive")
	}

	attempted := len(req.Envelopes)
	out := make([]TraceExportEnvelope, 0, len(req.Envelopes))
	truncated := false
	for _, e := range req.Envelopes {
		if len(out) >= HardMaxExportEnvelopes {
			truncated = true
			break
		}
		env, ok := scrubExportEnvelope(e, req.Job, req.Build)
		if !ok {
			continue
		}
		out = append(out, env)
	}
	// Soft default cap (still report truncation if we had more accepted than default
	// when caller sent more than DefaultMaxExportEnvelopes after scrub).
	if len(out) > DefaultMaxExportEnvelopes {
		out = out[:DefaultMaxExportEnvelopes]
		truncated = true
	}
	return TraceExportRequest{
		Job:       req.Job,
		Build:     req.Build,
		Envelopes: out,
	}, truncated || attempted > len(out), nil
}

// scrubExportEnvelope keeps allowlisted fields only and enforces id-like shapes.
// Returns ok=false when the envelope has no usable correlation fields.
func scrubExportEnvelope(e TraceExportEnvelope, job string, build int) (TraceExportEnvelope, bool) {
	out := TraceExportEnvelope{
		Job:   job,
		Build: build,
	}
	// Force job/build from request identity (ignore envelope overrides that
	// could smuggle alternate paths).
	traceID := strings.TrimSpace(strings.ToLower(e.TraceID))
	if isHexID(traceID, 1, MaxExportTraceIDLen) {
		out.TraceID = traceID
	}
	spanID := strings.TrimSpace(strings.ToLower(e.SpanID))
	if isHexID(spanID, 1, MaxExportSpanIDLen) {
		out.SpanID = spanID
	}
	svc := strings.TrimSpace(e.Service)
	if svc != "" && utf8Len(svc) <= MaxExportServiceLen && !looksLikeSecretish(svc) {
		out.Service = svc
	}
	fmtLabel := strings.TrimSpace(e.Format)
	if fmtLabel != "" && utf8Len(fmtLabel) <= MaxExportFormatLen && isSafeLabel(fmtLabel) {
		out.Format = fmtLabel
	}
	// Require at least one correlation field.
	if out.TraceID == "" && out.Service == "" {
		return TraceExportEnvelope{}, false
	}
	return out, true
}

func isHexID(s string, minLen, maxLen int) bool {
	if len(s) < minLen || len(s) > maxLen {
		return false
	}
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

func isSafeLabel(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) || r == '_' || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
}

// looksLikeSecretish rejects service labels that resemble tokens/passwords.
func looksLikeSecretish(s string) bool {
	lower := strings.ToLower(s)
	for _, needle := range []string{"password", "secret", "token", "api_key", "apikey", "bearer ", "ghp_", "glpat-"} {
		if strings.Contains(lower, needle) {
			return true
		}
	}
	// Long opaque base64-ish blobs are not service names.
	if len(s) > 64 {
		return true
	}
	return false
}

func utf8Len(s string) int {
	return len([]rune(s))
}

func finalizeExportResult(res TraceExportResult, req TraceExportRequest, truncated bool, backend string) TraceExportResult {
	if backend == "" {
		backend = "unknown"
	}
	if res.Backend == "" {
		res.Backend = backend
	}
	res.EvidenceSource = EvidenceSourceOtelExport
	res.Accepted = len(req.Envelopes)
	if res.Attempted == 0 {
		res.Attempted = res.Accepted
	}
	if truncated {
		res.Truncated = true
	}
	if res.Status == "" {
		switch {
		case res.Accepted == 0:
			res.Status = "empty"
		case backend == string(OtelExportBackendNoop):
			res.Status = "noop"
		case backend == string(OtelExportBackendMock):
			res.Status = "recorded"
		default:
			res.Status = "exported"
		}
	}
	hasResidual := false
	for _, r := range res.Residuals {
		if r == residualOtelExportClient {
			hasResidual = true
			break
		}
	}
	if !hasResidual {
		res.Residuals = append(res.Residuals, residualOtelExportClient)
	}
	return res
}

// --- backends: noop / mock ---

type noopExportBackend struct{}

func (n *noopExportBackend) Export(ctx context.Context, req TraceExportRequest) (TraceExportResult, error) {
	if err := ctx.Err(); err != nil {
		return TraceExportResult{}, err
	}
	return TraceExportResult{
		Status:    "noop",
		Backend:   "noop",
		Accepted:  len(req.Envelopes),
		Attempted: len(req.Envelopes),
		Message:   "otel-export noop backend: no collector configured (no network)",
	}, nil
}

type mockExportBackend struct {
	mu       sync.Mutex
	attempts []TraceExportRequest
}

func (m *mockExportBackend) Export(ctx context.Context, req TraceExportRequest) (TraceExportResult, error) {
	if err := ctx.Err(); err != nil {
		return TraceExportResult{}, err
	}
	// Deep-ish copy envelopes so later mutation cannot rewrite history.
	cp := TraceExportRequest{
		Job:       req.Job,
		Build:     req.Build,
		Envelopes: append([]TraceExportEnvelope(nil), req.Envelopes...),
	}
	m.mu.Lock()
	m.attempts = append(m.attempts, cp)
	n := len(m.attempts)
	m.mu.Unlock()
	return TraceExportResult{
		Status:    "recorded",
		Backend:   "mock",
		Accepted:  len(req.Envelopes),
		Attempted: len(req.Envelopes),
		Message:   fmt.Sprintf("mock otel-export backend recorded attempt #%d (no network)", n),
	}, nil
}

func (m *mockExportBackend) snapshot() []TraceExportRequest {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]TraceExportRequest, len(m.attempts))
	for i, a := range m.attempts {
		out[i] = TraceExportRequest{
			Job:       a.Job,
			Build:     a.Build,
			Envelopes: append([]TraceExportEnvelope(nil), a.Envelopes...),
		}
	}
	return out
}
