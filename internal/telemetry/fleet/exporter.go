package fleet

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Export body bounds (mirror gateway HTTPTokenFetcher discipline).
const (
	// MaxExportRequestBodyBytes caps the JSON POST body leaving the host.
	MaxExportRequestBodyBytes = 256 << 10 // 256 KiB (matches DefaultMaxBytes queue)
	// MaxExportResponseBodyBytes bounds response drain (never log body).
	MaxExportResponseBodyBytes = 64 << 10 // 64 KiB
	// DefaultExportTimeout is the HTTP client timeout when none is set.
	DefaultExportTimeout = 15 * time.Second
)

// ExportEnvelope is the POST body for batch export (versioned).
type ExportEnvelope struct {
	SchemaVersion int     `json:"schema_version"`
	Events        []Event `json:"events"`
}

// Exporter posts queued events to an optional HTTPS endpoint with backoff.
// Failures never propagate to the MCP serve path.
//
// Safety (mirrors gateway HTTPTokenFetcher):
//   - https-only URL (no http, no userinfo)
//   - no redirects
//   - request + response body caps; response body never included in errors
//   - never attaches Authorization from ambient env
type Exporter struct {
	mu         sync.Mutex
	url        string
	client     *http.Client
	backoff    time.Duration
	minBackoff time.Duration
	maxBackoff time.Duration
	lastErr    string
	lastOK     time.Time
	attempts   int64
	successes  int64
	failures   int64
}

// ExporterConfig configures optional remote export.
type ExporterConfig struct {
	// URL must be https without userinfo. Empty disables network export.
	// http is rejected (use httptest TLS in tests).
	URL string
	// Client optional; default refuses redirects and has a short timeout.
	// When set, CheckRedirect is still forced to refuse redirects.
	Client *http.Client
	// MinBackoff defaults to 5s; MaxBackoff defaults to 5m.
	MinBackoff time.Duration
	MaxBackoff time.Duration
}

// NewExporter builds an exporter. Empty URL is valid (no-op Post).
func NewExporter(cfg ExporterConfig) *Exporter {
	minB := cfg.MinBackoff
	if minB <= 0 {
		minB = 5 * time.Second
	}
	maxB := cfg.MaxBackoff
	if maxB <= 0 {
		maxB = 5 * time.Minute
	}
	return &Exporter{
		url:        strings.TrimSpace(cfg.URL),
		client:     cfg.Client,
		minBackoff: minB,
		maxBackoff: maxB,
		backoff:    minB,
	}
}

// URLConfigured reports whether an export URL is set.
func (e *Exporter) URLConfigured() bool {
	return e != nil && e.url != ""
}

// URLHost returns the host (no userinfo/path secrets) for status display.
func (e *Exporter) URLHost() string {
	if e == nil || e.url == "" {
		return ""
	}
	return SafeURLHost(e.url)
}

// SafeURLHost parses u and returns host only; strips userinfo.
func SafeURLHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return ""
	}
	// url.URL.Host does not include userinfo (User is separate).
	return u.Host
}

// ValidateExportURL checks https-only, host present, no userinfo.
func ValidateExportURL(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return errString("fleet: export URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errString("fleet: export URL is invalid")
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return errString("fleet: export URL must use https")
	}
	if u.User != nil {
		return errString("fleet: export URL must not contain userinfo")
	}
	return nil
}

// LastError returns a short, non-secret error class string for status.
func (e *Exporter) LastError() string {
	if e == nil {
		return ""
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastErr
}

// Stats returns attempt counters (secret-free).
func (e *Exporter) Stats() (attempts, successes, failures int64) {
	if e == nil {
		return 0, 0, 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.attempts, e.successes, e.failures
}

// Post sends events. Empty URL or empty events → no-op success.
// Never panics; returns error only for callers that want to apply backoff
// (serve path ignores errors).
func (e *Exporter) Post(ctx context.Context, events []Event) error {
	if e == nil || e.url == "" || len(events) == 0 {
		return nil
	}
	if err := ValidateExportURL(e.url); err != nil {
		e.recordFailure("invalid_url")
		return err
	}
	// Sanitize + validate each event again before leaving the host.
	sanitized := make([]Event, 0, len(events))
	for _, ev := range events {
		ev = SanitizeEvent(ev)
		raw, merr := MarshalEvent(ev)
		if merr != nil {
			e.recordFailure("event_marshal_error")
			return merr
		}
		if verr := ValidateExportJSON(raw); verr != nil {
			e.recordFailure("privacy_validation")
			return verr
		}
		sanitized = append(sanitized, ev)
	}
	env := ExportEnvelope{SchemaVersion: SchemaVersion, Events: sanitized}
	body, err := json.Marshal(env)
	if err != nil {
		e.recordFailure("marshal_error")
		return err
	}
	if len(body) > MaxExportRequestBodyBytes {
		e.recordFailure("request_oversize")
		return errString("fleet: export request body exceeds size limit")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.url, bytes.NewReader(body))
	if err != nil {
		e.recordFailure("request_build")
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "jenkins-mcp-fleet-telemetry/"+fmt.Sprintf("v%d", SchemaVersion))
	// Never attach Authorization from ambient env.
	client := e.httpClient()
	resp, err := client.Do(req)
	if err != nil {
		e.recordFailure("network_error")
		return err
	}
	defer resp.Body.Close()
	// Drain bounded body so connections can reuse; never include body in errors.
	limited, _ := io.ReadAll(io.LimitReader(resp.Body, MaxExportResponseBodyBytes+1))
	if len(limited) > MaxExportResponseBodyBytes {
		e.recordFailure("response_oversize")
		return errString("fleet: export response exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Class only — no body echo (may contain operator secrets).
		e.recordFailure(fmt.Sprintf("http_%d", resp.StatusCode))
		return errString(fmt.Sprintf("fleet: export HTTP %d", resp.StatusCode))
	}
	e.recordSuccess()
	return nil
}

// CurrentBackoff returns the next sleep duration after failures.
func (e *Exporter) CurrentBackoff() time.Duration {
	if e == nil {
		return 0
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.backoff
}

// DrainAndExport pops up to batchSize events and POSTs them.
// On failure, events are re-queued (prepend) best-effort by the caller via
// Requeue — this method returns failed events for requeue.
func (e *Exporter) DrainAndExport(ctx context.Context, q *Queue, batchSize int) (exported int, err error) {
	if e == nil || q == nil || !e.URLConfigured() {
		return 0, nil
	}
	if batchSize <= 0 {
		batchSize = 16
	}
	batch := q.Drain(batchSize)
	if len(batch) == 0 {
		return 0, nil
	}
	if err := e.Post(ctx, batch); err != nil {
		// Re-enqueue failed batch (may drop oldest if full — acceptable for MVP).
		for _, ev := range batch {
			q.Enqueue(ev)
		}
		return 0, err
	}
	return len(batch), nil
}

func (e *Exporter) httpClient() *http.Client {
	refuseRedirect := func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirect refused (fleet telemetry export pin)")
	}
	if e != nil && e.client != nil {
		c := *e.client
		c.CheckRedirect = refuseRedirect
		return &c
	}
	return &http.Client{
		Timeout:       DefaultExportTimeout,
		CheckRedirect: refuseRedirect,
	}
}

func (e *Exporter) recordFailure(class string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attempts++
	e.failures++
	e.lastErr = class
	next := e.backoff * 2
	if next < e.minBackoff {
		next = e.minBackoff
	}
	if next > e.maxBackoff {
		next = e.maxBackoff
	}
	// First failure after success starts at min.
	if e.backoff < e.minBackoff {
		e.backoff = e.minBackoff
	} else {
		e.backoff = next
	}
}

func (e *Exporter) recordSuccess() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.attempts++
	e.successes++
	e.lastErr = ""
	e.lastOK = time.Now().UTC()
	e.backoff = e.minBackoff
}
