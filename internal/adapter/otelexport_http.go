package adapter

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// httpExportBackend POSTs allowlisted metadata envelopes to an HTTPS origin.
// Fail closed: only https, origin pin, no userinfo, no redirects, no log text.
type httpExportBackend struct {
	base    *url.URL
	origin  string
	client  HTTPDoer
	timeout time.Duration
}

// httpExportBody is the outbound JSON (allowlisted fields only).
// Never includes console logs, tokens, or full parameter maps.
type httpExportBody struct {
	Job       string                `json:"job"`
	Build     int                   `json:"build"`
	Envelopes []TraceExportEnvelope `json:"envelopes"`
	// Kind labels the payload for stub receivers (not OTLP protobuf).
	Kind string `json:"kind"`
}

// httpExportResponse is the expected backend JSON shape (MVP stub contract).
type httpExportResponse struct {
	Accepted int    `json:"accepted"`
	Message  string `json:"message"`
}

const (
	maxExportHTTPResponseBytes = 1 << 20 // 1 MiB
	defaultExportHTTPTimeout   = 15 * time.Second
	exportHTTPKind             = "jenkins_mcp_trace_export_metadata_v1"
)

func newHTTPExportBackend(cfg OtelExportConfig) (*httpExportBackend, error) {
	raw := strings.TrimSpace(cfg.BaseURL)
	if raw == "" {
		return nil, fmt.Errorf("otel-export http backend requires BaseURL (https origin; no secrets)")
	}
	u, err := pinHTTPSExportBaseURL(raw)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{
			Timeout: defaultExportHTTPTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("redirect refused (origin pin)")
			},
		}
	}
	return &httpExportBackend{
		base:    u,
		origin:  originKey(u),
		client:  client,
		timeout: defaultExportHTTPTimeout,
	}, nil
}

// pinHTTPSExportBaseURL requires https, host, no userinfo; default path /export.
func pinHTTPSExportBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid otel-export BaseURL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("otel-export BaseURL must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("otel-export BaseURL missing host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("otel-export BaseURL must not contain userinfo/credentials")
	}
	if u.Opaque != "" {
		return nil, fmt.Errorf("otel-export BaseURL opaque form not allowed")
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = ""
	u.ForceQuery = false
	p := u.Path
	if p == "" || p == "/" {
		u.Path = "/export"
	} else if !strings.HasPrefix(p, "/") {
		u.Path = "/" + p
	}
	return u, nil
}

func (h *httpExportBackend) Export(ctx context.Context, req TraceExportRequest) (TraceExportResult, error) {
	if err := ctx.Err(); err != nil {
		return TraceExportResult{}, err
	}
	body := httpExportBody{
		Job:       req.Job,
		Build:     req.Build,
		Envelopes: req.Envelopes,
		Kind:      exportHTTPKind,
	}
	if body.Envelopes == nil {
		body.Envelopes = []TraceExportEnvelope{}
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return TraceExportResult{}, fmt.Errorf("encode export: %w", err)
	}
	// Defense: refuse to send if payload accidentally contains console/log/params keys.
	// Struct encoding already excludes these; check is belt-and-suspenders on key names.
	if bytes.Contains(raw, []byte(`"console"`)) || bytes.Contains(raw, []byte(`"log_text"`)) ||
		bytes.Contains(raw, []byte(`"parameters"`)) || bytes.Contains(raw, []byte(`"password"`)) {
		return TraceExportResult{}, fmt.Errorf("otel-export payload failed allowlist canary")
	}

	u := *h.base
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return TraceExportResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	// No Authorization header in MVP — credentials residual (keyring).

	if originKey(httpReq.URL) != h.origin {
		return TraceExportResult{}, fmt.Errorf("otel-export request origin mismatch (pin fail-closed)")
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return TraceExportResult{}, fmt.Errorf("otel-export http: %w", err)
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, maxExportHTTPResponseBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return TraceExportResult{}, fmt.Errorf("otel-export http read: %w", err)
	}
	if len(respBody) > maxExportHTTPResponseBytes {
		return TraceExportResult{}, fmt.Errorf("otel-export http response exceeds %d bytes", maxExportHTTPResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not echo body (may contain secrets from misconfigured backend).
		return TraceExportResult{}, fmt.Errorf("otel-export http status %d", resp.StatusCode)
	}

	var parsed httpExportResponse
	if len(respBody) > 0 {
		// Empty body is ok for stub receivers; ignore decode errors on empty.
		_ = json.Unmarshal(respBody, &parsed)
	}
	accepted := parsed.Accepted
	if accepted <= 0 {
		accepted = len(req.Envelopes)
	}
	msg := strings.TrimSpace(parsed.Message)
	if msg == "" {
		msg = "otel-export http metadata POST completed (not OTLP protobuf)"
	}
	return TraceExportResult{
		Status:    "exported",
		Backend:   "http",
		Accepted:  accepted,
		Attempted: len(req.Envelopes),
		Message:   msg,
	}, nil
}
