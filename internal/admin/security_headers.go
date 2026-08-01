package admin

import "net/http"

// DefaultContentSecurityPolicy is the strict CSP for the admin SPA + BFF (UI-008).
//
// style-src includes 'unsafe-inline' because the Vite/React production CSS may
// inject small style attributes; scripts remain 'self' only (no CDN, no inline
// script). connect-src 'self' keeps BFF same-origin. object-src/base-uri/frame-ancestors
// harden residual XSS and clickjacking.
//
// Reverse-proxy residual: prefer same-origin (assets + /admin/v1 on one host).
// Proxies must not strip or weaken these headers carelessly; if TLS terminates
// upstream, re-apply CSP on the edge or pass through the origin response.
const DefaultContentSecurityPolicy = "" +
	"default-src 'self'; " +
	"script-src 'self'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data:; " +
	"connect-src 'self'; " +
	"object-src 'none'; " +
	"base-uri 'self'; " +
	"frame-ancestors 'none'"

// DefaultPermissionsPolicy is a minimal residual Permissions-Policy (UI-008).
const DefaultPermissionsPolicy = "camera=(), microphone=(), geolocation=()"

// securityHeaders wraps next and sets security headers on every response.
// Headers are set before the next handler runs so JSON API content-types and
// body writers are preserved (we never overwrite Content-Type).
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if w == nil {
			return
		}
		h := w.Header()
		h.Set("Content-Security-Policy", DefaultContentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", DefaultPermissionsPolicy)
		if next != nil {
			next.ServeHTTP(w, r)
		}
	})
}
