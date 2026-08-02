package mcpserver_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hilather/go-jenkins-mcp/internal/mcpserver"
)

// TestHOST002_StreamableHTTPOriginHostMatrix is the expanded offline HOST-002
// residual-lite fixture matrix for Streamable HTTP Host/Origin fail-closed
// policy (as coded in checkOrigin / checkRequestHost / protectHandler).
//
// Covers:
//   - missing Origin on non-GET → allow (non-browser clients; policy as coded)
//   - wrong Origin → 403
//   - exact AllowedOrigins match → pass protect
//   - Host not in AllowedHosts (non-local) → 403
//   - X-Forwarded-Host / X-Forwarded-Origin ignored (TrustedProxy=false)
//   - TrustedProxy=true residual still ignores X-Forwarded-* (no-op honesty)
//   - PathPrefix strip does not weaken Origin checks
//
// Secret canary: error bodies never echo the BearerToken.
// Live reverse-proxy edge rewrite remains NET-001 residual — not claimed here.
func TestHOST002_StreamableHTTPOriginHostMatrix(t *testing.T) {
	t.Parallel()
	const (
		allowedOrig = "https://portal.example.corp"
		allowedHost = "mcp.example.corp"
		prefix      = "/mcp"
	)

	type want struct {
		status      int
		passProtect bool // not protect-layer 401/403/404 (SDK may still 4xx)
		bodySubstr  string
	}
	type row struct {
		name         string
		pathPrefix   string
		trustedProxy bool
		method       string
		path         string
		host         string
		// originUnset leaves Origin header absent (distinct from empty string set).
		originUnset  bool
		origin       string
		extraHeaders map[string]string
		want         want
	}

	rows := []row{
		// --- missing Origin on non-GET (policy: allow non-browser clients) ---
		{
			name:        "missing_origin_non_get_non_local_allow",
			method:      http.MethodPost,
			path:        "/",
			host:        allowedHost,
			originUnset: true,
			want:        want{passProtect: true},
		},
		{
			name:        "missing_origin_non_get_under_path_prefix_allow",
			pathPrefix:  prefix,
			method:      http.MethodPost,
			path:        prefix,
			host:        allowedHost,
			originUnset: true,
			want:        want{passProtect: true},
		},
		// --- wrong Origin → reject ---
		{
			name:   "wrong_origin_reject",
			method: http.MethodPost,
			path:   "/",
			host:   allowedHost,
			origin: "https://evil.example",
			want:   want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
		// --- exact AllowedOrigins match → accept ---
		{
			name:   "exact_allowed_origin_accept",
			method: http.MethodPost,
			path:   "/",
			host:   allowedHost,
			origin: allowedOrig,
			want:   want{passProtect: true},
		},
		// --- Host not in AllowedHosts when required (non-local) ---
		{
			name:   "host_not_in_allowed_hosts_reject",
			method: http.MethodPost,
			path:   "/",
			host:   "evil.example",
			origin: allowedOrig,
			want:   want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		// --- X-Forwarded-* ignored when TrustedProxy=false (default) ---
		{
			name:   "x_forwarded_host_ignored_trusted_proxy_false",
			method: http.MethodPost,
			path:   "/",
			host:   "evil.example",
			origin: allowedOrig,
			extraHeaders: map[string]string{
				"X-Forwarded-Host": allowedHost,
			},
			want: want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		{
			// Spoofed X-Forwarded-Origin must not override a wrong Origin header.
			name:   "x_forwarded_origin_ignored_trusted_proxy_false",
			method: http.MethodPost,
			path:   "/",
			host:   allowedHost,
			origin: "https://evil.example",
			extraHeaders: map[string]string{
				"X-Forwarded-Origin": allowedOrig,
			},
			want: want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
		{
			// Missing Origin + only X-Forwarded-Origin still "missing Origin" policy
			// (allow) — proves X-Forwarded-Origin is not treated as Origin.
			// Regression: if code ever trusted XFO as Origin, wrong/malformed
			// values could start failing; here allowed-looking XFO must not matter.
			name:        "x_forwarded_origin_not_used_as_origin_when_origin_missing",
			method:      http.MethodPost,
			path:        "/",
			host:        allowedHost,
			originUnset: true,
			extraHeaders: map[string]string{
				"X-Forwarded-Origin": "https://evil.example",
			},
			want: want{passProtect: true},
		},
		// --- TrustedProxy=true residual still ignores X-Forwarded-* (no-op honesty) ---
		{
			name:         "trusted_proxy_true_still_ignores_x_forwarded_host",
			trustedProxy: true,
			method:       http.MethodPost,
			path:         "/",
			host:         "evil.example",
			origin:       allowedOrig,
			extraHeaders: map[string]string{
				"X-Forwarded-Host": allowedHost,
			},
			want: want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		{
			name:         "trusted_proxy_true_still_ignores_x_forwarded_origin",
			trustedProxy: true,
			method:       http.MethodPost,
			path:         "/",
			host:         allowedHost,
			origin:       "https://evil.example",
			extraHeaders: map[string]string{
				"X-Forwarded-Origin": allowedOrig,
			},
			want: want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
		// --- PathPrefix strip does not weaken Origin checks ---
		{
			name:       "path_prefix_strip_wrong_origin_still_403",
			pathPrefix: prefix,
			method:     http.MethodPost,
			path:       prefix,
			host:       allowedHost,
			origin:     "https://evil.example",
			want:       want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
		{
			name:       "path_prefix_strip_exact_origin_accept",
			pathPrefix: prefix,
			method:     http.MethodPost,
			path:       prefix + "/messages",
			host:       allowedHost,
			origin:     allowedOrig,
			want:       want{passProtect: true},
		},
		{
			// After strip, Host allow-list still applies (not weakened by prefix).
			name:       "path_prefix_strip_bad_host_still_403",
			pathPrefix: prefix,
			method:     http.MethodPost,
			path:       prefix,
			host:       "evil.example",
			origin:     allowedOrig,
			want:       want{status: http.StatusForbidden, bodySubstr: "Host"},
		},
		{
			// X-Forwarded-Prefix + wrong Origin under prefix: Origin still enforced.
			name:       "path_prefix_x_forwarded_does_not_bypass_origin",
			pathPrefix: prefix,
			method:     http.MethodPost,
			path:       prefix,
			host:       allowedHost,
			origin:     "https://evil.example",
			extraHeaders: map[string]string{
				"X-Forwarded-Prefix": prefix,
				"X-Forwarded-Host":   allowedHost,
				"X-Forwarded-Origin": allowedOrig,
			},
			want: want{status: http.StatusForbidden, bodySubstr: "Origin"},
		},
	}

	// Pre-build handlers per (pathPrefix, trustedProxy) before parallel subtests
	// (map is read-only after this loop — no concurrent write).
	type handlerKey struct {
		prefix       string
		trustedProxy bool
	}
	handlers := make(map[handlerKey]http.Handler)
	for _, tc := range rows {
		k := handlerKey{prefix: tc.pathPrefix, trustedProxy: tc.trustedProxy}
		if _, ok := handlers[k]; ok {
			continue
		}
		srv := mcpserver.NewServer("test", "0.0.1")
		cfg := mcpserver.DefaultHTTPConfig()
		cfg.PathPrefix = tc.pathPrefix
		cfg.AllowNonLocal = true
		cfg.AllowedOrigins = []string{allowedOrig}
		cfg.AllowedHosts = []string{allowedHost}
		cfg.BearerToken = canaryHTTPToken
		cfg.LabIdentity = true
		cfg.TrustedProxy = tc.trustedProxy
		h, err := mcpserver.NewHTTPHandler(srv, cfg)
		if err != nil {
			t.Fatalf("NewHTTPHandler pathPrefix=%q trustedProxy=%v: %v", tc.pathPrefix, tc.trustedProxy, err)
		}
		handlers[k] = h
	}

	for _, tc := range rows {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := handlers[handlerKey{prefix: tc.pathPrefix, trustedProxy: tc.trustedProxy}]
			if h == nil {
				t.Fatal("missing prebuilt handler")
			}
			method := tc.method
			if method == "" {
				method = http.MethodPost
			}
			path := tc.path
			if path == "" {
				path = "/"
			}
			req := httptest.NewRequest(method, "http://"+tc.host+path, strings.NewReader(`{}`))
			req.Host = tc.host
			if !tc.originUnset && tc.origin != "" {
				req.Header.Set("Origin", tc.origin)
			}
			// originUnset: leave Origin absent. origin=="" with originUnset false also
			// leaves it unset (policy same); explicit only when needed.
			if method != http.MethodGet && method != http.MethodHead {
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set("Accept", "application/json, text/event-stream")
			}
			req.Header.Set("Authorization", "Bearer "+canaryHTTPToken)
			req.Header.Set(mcpserver.HeaderLabSubject, "lab-user-1")
			for k, v := range tc.extraHeaders {
				req.Header.Set(k, v)
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			body := rr.Body.String()
			// Secret-free: never echo shared secret, Authorization, or canary token.
			if strings.Contains(body, canaryHTTPToken) {
				t.Fatalf("response leaked token canary: %s", body)
			}
			if strings.Contains(strings.ToLower(body), "authorization") {
				t.Fatalf("response should not mention authorization: %s", body)
			}
			if strings.Contains(body, "Bearer ") {
				t.Fatalf("response leaked Bearer scheme: %s", body)
			}
			if tc.want.passProtect {
				if rr.Code == http.StatusForbidden || rr.Code == http.StatusUnauthorized || rr.Code == http.StatusNotFound {
					t.Fatalf("want pass protect, got status=%d body=%s", rr.Code, body)
				}
				return
			}
			if rr.Code != tc.want.status {
				t.Fatalf("status=%d want %d body=%s", rr.Code, tc.want.status, body)
			}
			if tc.want.bodySubstr != "" && !strings.Contains(body, tc.want.bodySubstr) {
				t.Fatalf("body missing %q: %s", tc.want.bodySubstr, body)
			}
		})
	}
}
