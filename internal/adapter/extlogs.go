package adapter

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// INT-003 built-in adapter ID: external log-system query framework (MVP stub).
// No real Splunk/ELK client; backends are noop, mock, or optional HTTPS JSON.
const IDExtLogs = "ext-logs"

// ExtLogsBackendName selects the query backend for the ext-logs adapter.
type ExtLogsBackendName string

const (
	// ExtLogsBackendNoop returns empty results (default when enabled without config).
	ExtLogsBackendNoop ExtLogsBackendName = "noop"
	// ExtLogsBackendMock returns deterministic fake entry refs for tests.
	ExtLogsBackendMock ExtLogsBackendName = "mock"
	// ExtLogsBackendHTTP posts a bounded JSON query to an allowlisted HTTPS origin.
	ExtLogsBackendHTTP ExtLogsBackendName = "http"
)

// Bounds for external log queries (INT-003). Model cannot submit unrestricted
// backend query languages; query string is a short free-text filter only.
const (
	// DefaultMaxLogEntries is the default cap on entry refs returned.
	DefaultMaxLogEntries = 20
	// HardMaxLogEntries is the absolute ceiling.
	HardMaxLogEntries = 50
	// MaxLogQueryLen is the maximum accepted query string length (runes).
	MaxLogQueryLen = 256
	// MaxLogExcerptBytes bounds each excerpt before redaction (UTF-8 bytes).
	MaxLogExcerptBytes = 256
	// DefaultMaxLogTimeRange is the default max Start→End window.
	DefaultMaxLogTimeRange = 24 * time.Hour
	// HardMaxLogTimeRange is the absolute max time window.
	HardMaxLogTimeRange = 7 * 24 * time.Hour
	// EvidenceSourceExternalLogs labels external-system evidence (not Jenkins console).
	EvidenceSourceExternalLogs = "external_log_system"
)

// ExternalLogQueryRequest is a bounded query keyed by Jenkins job/build identity.
// It is intentionally not a full console dump and not an arbitrary backend DSL.
type ExternalLogQueryRequest struct {
	// Job is the Jenkins job full name (folder/job path).
	Job string
	// Build is the Jenkins build number.
	Build int
	// Start / End bound the search window (UTC preferred). Zero End ⇒ now.
	// Window longer than HardMaxLogTimeRange is rejected; longer than configured
	// max is clamped with Truncated=true on the result when applicable.
	Start time.Time
	End   time.Time
	// Query is a short free-text filter (max MaxLogQueryLen). Not passthrough QL.
	Query string
	// MaxEntries caps returned refs (0 ⇒ default; hard-capped).
	MaxEntries int
}

// ExternalLogEntryRef is one bounded external log hit (ref + short excerpt).
type ExternalLogEntryRef struct {
	// RefID is a backend-specific opaque reference (not a secret).
	RefID string `json:"ref_id"`
	// Excerpt is a short text snippet (caller/tools must redact before model).
	Excerpt string `json:"excerpt,omitempty"`
	// Timestamp is RFC3339 when known.
	Timestamp string `json:"timestamp,omitempty"`
	// SourceLabel identifies the external system (e.g. "mock", "http", "noop").
	SourceLabel string `json:"source_label"`
	// Freshness labels data age path (e.g. "live", "cached", "stub").
	Freshness string `json:"freshness"`
	// EvidenceSource is always external_log_system for this adapter family.
	EvidenceSource string `json:"evidence_source"`
}

// ExternalLogQueryResult is the bounded query outcome.
type ExternalLogQueryResult struct {
	Entries []ExternalLogEntryRef `json:"entries"`
	// Count is len(Entries).
	Count int `json:"count"`
	// Truncated when more hits existed than returned or time window was clamped.
	Truncated bool `json:"truncated,omitempty"`
	// MaxEntries is the effective entry cap applied.
	MaxEntries int `json:"max_entries"`
	// SourceLabel is the backend source (e.g. mock/http/noop).
	SourceLabel string `json:"source_label"`
	// Freshness for the result set.
	Freshness string `json:"freshness"`
	// EvidenceSource for the result set.
	EvidenceSource string `json:"evidence_source"`
	// Residuals document missing real SaaS clients / limits.
	Residuals []string `json:"residuals,omitempty"`
	// Message is a short status when empty or stubbed.
	Message string `json:"message,omitempty"`
}

// ExternalLogQuery is the capability surface for external log backends.
// Implemented by ExtLogs (and tests). Does not receive Jenkins credentials.
type ExternalLogQuery interface {
	QueryExternalLogs(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error)
}

// ExtLogsConfig configures the ext-logs adapter factory (paths/refs only; no secrets).
type ExtLogsConfig struct {
	// Backend selects noop|mock|http (default noop).
	Backend ExtLogsBackendName
	// BaseURL is the allowlisted HTTPS origin for the http backend (required for http).
	// Paths and origin only — credentials are residual (keyring namespace).
	BaseURL string
	// MaxTimeRange clamps request windows (0 ⇒ DefaultMaxLogTimeRange; hard-capped).
	MaxTimeRange time.Duration
	// HTTP is optional for tests; nil uses a timeout client for production http.
	// Never inject a client that carries Jenkins credentials.
	HTTP HTTPDoer
}

// residualExtLogsSaaS is returned so operators know real Splunk/ELK clients remain open.
const residualExtLogsSaaS = "real Splunk/ELK/Datadog log API client residual (INT-003 MVP: noop/mock/optional HTTPS JSON stub only)"

// ExtLogs is the INT-003 external log adapter (lifecycle + ExternalLogQuery).
type ExtLogs struct {
	host    Host
	cfg     ExtLogsConfig
	backend LogBackend

	mu      sync.Mutex
	started bool
	stopped bool
}

// ExtLogsFactory returns a Factory that builds ExtLogs with the given config.
func ExtLogsFactory(cfg ExtLogsConfig) Factory {
	return func(host Host) (Adapter, error) {
		return NewExtLogs(host, cfg)
	}
}

// NewExtLogs constructs the ext-logs adapter. Backend defaults to noop.
func NewExtLogs(host Host, cfg ExtLogsConfig) (Adapter, error) {
	cfg = normalizeExtLogsConfig(cfg)
	backend, err := newLogBackend(cfg)
	if err != nil {
		return nil, err
	}
	return &ExtLogs{host: host, cfg: cfg, backend: backend}, nil
}

// NewExtLogsDefault is the DefaultCatalog factory (noop backend; no network).
func NewExtLogsDefault(host Host) (Adapter, error) {
	return NewExtLogs(host, ExtLogsConfig{Backend: ExtLogsBackendNoop})
}

func normalizeExtLogsConfig(cfg ExtLogsConfig) ExtLogsConfig {
	switch strings.ToLower(strings.TrimSpace(string(cfg.Backend))) {
	case "", string(ExtLogsBackendNoop):
		cfg.Backend = ExtLogsBackendNoop
	case string(ExtLogsBackendMock):
		cfg.Backend = ExtLogsBackendMock
	case string(ExtLogsBackendHTTP):
		cfg.Backend = ExtLogsBackendHTTP
	default:
		// Unknown → fail later in newLogBackend via explicit error path;
		// keep string for error message.
		cfg.Backend = ExtLogsBackendName(strings.ToLower(strings.TrimSpace(string(cfg.Backend))))
	}
	if cfg.MaxTimeRange <= 0 {
		cfg.MaxTimeRange = DefaultMaxLogTimeRange
	}
	if cfg.MaxTimeRange > HardMaxLogTimeRange {
		cfg.MaxTimeRange = HardMaxLogTimeRange
	}
	return cfg
}

func newLogBackend(cfg ExtLogsConfig) (LogBackend, error) {
	switch cfg.Backend {
	case ExtLogsBackendNoop:
		return &noopLogBackend{}, nil
	case ExtLogsBackendMock:
		return &mockLogBackend{}, nil
	case ExtLogsBackendHTTP:
		return newHTTPLogBackend(cfg)
	default:
		return nil, fmt.Errorf("unknown ext-logs backend %q (want noop|mock|http)", cfg.Backend)
	}
}

func (e *ExtLogs) ID() string { return IDExtLogs }

func (e *ExtLogs) Capabilities() []Capability {
	return []Capability{CapLifecycle, CapExternalLogs}
}

func (e *ExtLogs) Start(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	e.mu.Lock()
	e.started = true
	e.stopped = false
	e.mu.Unlock()
	e.host.logf("adapter ext-logs: started backend=%s (no Jenkins credentials)", e.cfg.Backend)
	return nil
}

func (e *ExtLogs) Stop(ctx context.Context) error {
	_ = ctx
	e.mu.Lock()
	e.stopped = true
	e.started = false
	e.mu.Unlock()
	e.host.logf("adapter ext-logs: stopped")
	return nil
}

func (e *ExtLogs) Health(ctx context.Context) Health {
	_ = ctx
	e.mu.Lock()
	defer e.mu.Unlock()
	switch {
	case e.stopped && !e.started:
		return Health{Status: HealthStopped, Message: "stopped", CheckedAt: e.host.now()}
	case e.started:
		return Health{
			Status:    HealthHealthy,
			Message:   fmt.Sprintf("external logs enabled (backend=%s; job/build query only)", e.cfg.Backend),
			CheckedAt: e.host.now(),
		}
	default:
		return Health{Status: HealthUnknown, Message: "not started", CheckedAt: e.host.now()}
	}
}

// QueryExternalLogs implements ExternalLogQuery with bounds + start gate.
// Callers should use adapter.Call for panic isolation + rate limit.
func (e *ExtLogs) QueryExternalLogs(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error) {
	if err := ctx.Err(); err != nil {
		return ExternalLogQueryResult{}, err
	}
	e.mu.Lock()
	started := e.started
	e.mu.Unlock()
	if !started {
		return ExternalLogQueryResult{}, fmt.Errorf("adapter %q is not started", IDExtLogs)
	}
	norm, err := normalizeLogQuery(req, e.cfg.MaxTimeRange)
	if err != nil {
		return ExternalLogQueryResult{}, err
	}
	res, err := e.backend.Query(ctx, norm)
	if err != nil {
		return ExternalLogQueryResult{}, err
	}
	// Enforce excerpt/entry bounds on every backend result.
	res = finalizeLogResult(res, norm.MaxEntries, string(e.cfg.Backend))
	return res, nil
}

// LogBackend is the pluggable query engine behind ExtLogs.
type LogBackend interface {
	Query(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error)
}

// normalizeLogQuery validates and clamps a request (fail closed on bad identity).
func normalizeLogQuery(req ExternalLogQueryRequest, maxRange time.Duration) (ExternalLogQueryRequest, error) {
	req.Job = strings.TrimSpace(req.Job)
	if req.Job == "" {
		return ExternalLogQueryRequest{}, fmt.Errorf("job is required")
	}
	if strings.Contains(req.Job, "://") {
		return ExternalLogQueryRequest{}, fmt.Errorf("job must be a typed path, not a URL")
	}
	if req.Build <= 0 {
		return ExternalLogQueryRequest{}, fmt.Errorf("build must be positive")
	}
	// Query length (runes for user-facing bound).
	q := strings.TrimSpace(req.Query)
	if utf8.RuneCountInString(q) > MaxLogQueryLen {
		return ExternalLogQueryRequest{}, fmt.Errorf("query exceeds max length %d", MaxLogQueryLen)
	}
	req.Query = q

	maxEntries := req.MaxEntries
	if maxEntries <= 0 {
		maxEntries = DefaultMaxLogEntries
	}
	if maxEntries > HardMaxLogEntries {
		maxEntries = HardMaxLogEntries
	}
	req.MaxEntries = maxEntries

	if maxRange <= 0 {
		maxRange = DefaultMaxLogTimeRange
	}
	if maxRange > HardMaxLogTimeRange {
		maxRange = HardMaxLogTimeRange
	}

	end := req.End
	if end.IsZero() {
		end = time.Now().UTC()
	} else {
		end = end.UTC()
	}
	start := req.Start
	if start.IsZero() {
		start = end.Add(-maxRange)
	} else {
		start = start.UTC()
	}
	if end.Before(start) {
		return ExternalLogQueryRequest{}, fmt.Errorf("end must be after start")
	}
	if end.Sub(start) > maxRange {
		start = end.Add(-maxRange)
	}
	// Absolute hard window (defense in depth).
	if end.Sub(start) > HardMaxLogTimeRange {
		start = end.Add(-HardMaxLogTimeRange)
	}
	req.Start = start
	req.End = end
	return req, nil
}

func finalizeLogResult(res ExternalLogQueryResult, maxEntries int, source string) ExternalLogQueryResult {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxLogEntries
	}
	if maxEntries > HardMaxLogEntries {
		maxEntries = HardMaxLogEntries
	}
	if source == "" {
		source = "unknown"
	}
	if res.SourceLabel == "" {
		res.SourceLabel = source
	}
	if res.Freshness == "" {
		res.Freshness = "stub"
	}
	res.EvidenceSource = EvidenceSourceExternalLogs
	res.MaxEntries = maxEntries

	// Bound entries + excerpts.
	if len(res.Entries) > maxEntries {
		res.Entries = res.Entries[:maxEntries]
		res.Truncated = true
	}
	for i := range res.Entries {
		e := &res.Entries[i]
		e.Excerpt = truncateBytes(e.Excerpt, MaxLogExcerptBytes)
		if e.SourceLabel == "" {
			e.SourceLabel = res.SourceLabel
		}
		if e.Freshness == "" {
			e.Freshness = res.Freshness
		}
		e.EvidenceSource = EvidenceSourceExternalLogs
		// Never return empty ref_id for a present entry — drop such rows.
	}
	// Filter empty ref ids.
	out := res.Entries[:0]
	for _, e := range res.Entries {
		if strings.TrimSpace(e.RefID) == "" {
			continue
		}
		out = append(out, e)
	}
	res.Entries = out
	if res.Entries == nil {
		res.Entries = []ExternalLogEntryRef{}
	}
	res.Count = len(res.Entries)

	// Always surface SaaS residual for MVP.
	hasResidual := false
	for _, r := range res.Residuals {
		if r == residualExtLogsSaaS {
			hasResidual = true
			break
		}
	}
	if !hasResidual {
		res.Residuals = append(res.Residuals, residualExtLogsSaaS)
	}
	return res
}

func truncateBytes(s string, max int) string {
	if max <= 0 || len(s) <= max {
		return s
	}
	// Avoid cutting mid-rune.
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	if max <= 0 {
		return ""
	}
	return s[:max]
}

// --- backends: noop / mock ---

type noopLogBackend struct{}

func (n *noopLogBackend) Query(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error) {
	if err := ctx.Err(); err != nil {
		return ExternalLogQueryResult{}, err
	}
	return ExternalLogQueryResult{
		Entries:     []ExternalLogEntryRef{},
		SourceLabel: "noop",
		Freshness:   "stub",
		Message:     "ext-logs noop backend: no external system configured",
	}, nil
}

type mockLogBackend struct{}

func (m *mockLogBackend) Query(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error) {
	if err := ctx.Err(); err != nil {
		return ExternalLogQueryResult{}, err
	}
	// Deterministic fake refs keyed by job/build — never secrets.
	n := req.MaxEntries
	if n > 3 {
		n = 3 // mock returns at most 3 sample hits
	}
	entries := make([]ExternalLogEntryRef, 0, n)
	for i := 0; i < n; i++ {
		entries = append(entries, ExternalLogEntryRef{
			RefID:       fmt.Sprintf("mock:%s#%d:%d", req.Job, req.Build, i+1),
			Excerpt:     fmt.Sprintf("mock external log hit %d for %s #%d query=%q", i+1, req.Job, req.Build, req.Query),
			Timestamp:   req.End.UTC().Format(time.RFC3339),
			SourceLabel: "mock",
			Freshness:   "stub",
		})
	}
	return ExternalLogQueryResult{
		Entries:     entries,
		SourceLabel: "mock",
		Freshness:   "stub",
		Message:     "mock external log backend (no network)",
	}, nil
}
