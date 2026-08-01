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

// HTTPDoer is the narrow HTTP surface used by the optional JSON log backend.
// *http.Client implements it. Never pass a client that injects Jenkins auth.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// httpLogBackend posts a bounded JSON query to an allowlisted HTTPS origin.
// Fail closed: only https, origin pin (scheme+host[+port]), no redirects to other origins.
type httpLogBackend struct {
	base    *url.URL // normalized origin + optional path prefix
	origin  string   // scheme://host[:port] for pin checks
	client  HTTPDoer
	timeout time.Duration
}

// httpQueryBody is the outbound JSON (job/build identity only + bounds).
// No credentials. No full console dump.
type httpQueryBody struct {
	Job        string `json:"job"`
	Build      int    `json:"build"`
	Start      string `json:"start"` // RFC3339
	End        string `json:"end"`
	Query      string `json:"query,omitempty"`
	MaxEntries int    `json:"max_entries"`
}

// httpQueryResponse is the expected backend JSON shape (MVP stub contract).
type httpQueryResponse struct {
	Entries []struct {
		RefID     string `json:"ref_id"`
		Excerpt   string `json:"excerpt"`
		Timestamp string `json:"timestamp"`
	} `json:"entries"`
	Truncated bool   `json:"truncated"`
	Message   string `json:"message"`
}

const (
	maxHTTPResponseBytes = 1 << 20 // 1 MiB response body cap
	defaultHTTPTimeout   = 15 * time.Second
)

func newHTTPLogBackend(cfg ExtLogsConfig) (*httpLogBackend, error) {
	raw := strings.TrimSpace(cfg.BaseURL)
	if raw == "" {
		return nil, fmt.Errorf("ext-logs http backend requires BaseURL (https origin; no secrets)")
	}
	u, err := pinHTTPSBaseURL(raw)
	if err != nil {
		return nil, err
	}
	client := cfg.HTTP
	if client == nil {
		client = &http.Client{
			Timeout: defaultHTTPTimeout,
			// Fail closed: no redirects (would break origin pin).
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return fmt.Errorf("redirect refused (origin pin)")
			},
		}
	}
	return &httpLogBackend{
		base:    u,
		origin:  originKey(u),
		client:  client,
		timeout: defaultHTTPTimeout,
	}, nil
}

// pinHTTPSBaseURL requires https, host, no userinfo, strips query/fragment.
func pinHTTPSBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("invalid ext-logs BaseURL: %w", err)
	}
	if !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("ext-logs BaseURL must use https (got %q)", u.Scheme)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("ext-logs BaseURL missing host")
	}
	if u.User != nil {
		return nil, fmt.Errorf("ext-logs BaseURL must not contain userinfo/credentials")
	}
	if u.Opaque != "" {
		return nil, fmt.Errorf("ext-logs BaseURL opaque form not allowed")
	}
	u.Fragment = ""
	u.RawFragment = ""
	u.RawQuery = ""
	u.ForceQuery = false
	// Normalize path: empty → /query default endpoint path for MVP.
	p := u.Path
	if p == "" || p == "/" {
		u.Path = "/query"
	} else {
		// Keep operator path prefix; ensure leading slash.
		if !strings.HasPrefix(p, "/") {
			u.Path = "/" + p
		}
	}
	return u, nil
}

func originKey(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + strings.ToLower(u.Host)
}

func (h *httpLogBackend) Query(ctx context.Context, req ExternalLogQueryRequest) (ExternalLogQueryResult, error) {
	if err := ctx.Err(); err != nil {
		return ExternalLogQueryResult{}, err
	}
	body := httpQueryBody{
		Job:        req.Job,
		Build:      req.Build,
		Start:      req.Start.UTC().Format(time.RFC3339),
		End:        req.End.UTC().Format(time.RFC3339),
		Query:      req.Query,
		MaxEntries: req.MaxEntries,
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return ExternalLogQueryResult{}, fmt.Errorf("encode query: %w", err)
	}

	// Build request URL from pinned base (path already set).
	u := *h.base
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(raw))
	if err != nil {
		return ExternalLogQueryResult{}, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	// No Authorization header in MVP — credentials residual (keyring).

	// Origin pin: refuse if request URL drifts.
	if originKey(httpReq.URL) != h.origin {
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs request origin mismatch (pin fail-closed)")
	}

	resp, err := h.client.Do(httpReq)
	if err != nil {
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs http query: %w", err)
	}
	defer resp.Body.Close()

	// Bound read.
	limited := io.LimitReader(resp.Body, maxHTTPResponseBytes+1)
	respBody, err := io.ReadAll(limited)
	if err != nil {
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs http read: %w", err)
	}
	if len(respBody) > maxHTTPResponseBytes {
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs http response exceeds %d bytes", maxHTTPResponseBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// Do not echo body (may contain secrets from misconfigured backend).
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs http status %d", resp.StatusCode)
	}

	var parsed httpQueryResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return ExternalLogQueryResult{}, fmt.Errorf("ext-logs http json: %w", err)
	}

	entries := make([]ExternalLogEntryRef, 0, len(parsed.Entries))
	for _, e := range parsed.Entries {
		ref := strings.TrimSpace(e.RefID)
		if ref == "" {
			continue
		}
		entries = append(entries, ExternalLogEntryRef{
			RefID:       ref,
			Excerpt:     e.Excerpt,
			Timestamp:   strings.TrimSpace(e.Timestamp),
			SourceLabel: "http",
			Freshness:   "live",
		})
	}
	return ExternalLogQueryResult{
		Entries:     entries,
		Truncated:   parsed.Truncated,
		SourceLabel: "http",
		Freshness:   "live",
		Message:     strings.TrimSpace(parsed.Message),
	}, nil
}
