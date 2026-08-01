package admin

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// HeaderAdminToken is the alternate client header for the admin shared secret
// (exact match). Prefer Authorization: Bearer when both are usable.
const HeaderAdminToken = "X-Jenkins-MCP-Admin-Token"

// ctxKeyRole carries the configured admin Role on the request context.
type ctxKeyRole struct{}

// WithRole returns a child context with role attached.
func WithRole(ctx context.Context, role Role) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, ctxKeyRole{}, role)
}

// RoleFromContext returns the admin Role from ctx. Missing values yield empty
// Role (fail closed: Can denies all perms). authMiddleware always attaches
// the process Role before handlers run.
func RoleFromContext(ctx context.Context) Role {
	if ctx == nil {
		return ""
	}
	r, _ := ctx.Value(ctxKeyRole{}).(Role)
	return r
}

// TokenMatches reports whether r presents want via Authorization: Bearer or
// X-Jenkins-MCP-Admin-Token (exact match, constant-time). Empty want always
// matches (no gate). Never logs token values.
func TokenMatches(r *http.Request, want string) bool {
	if want == "" {
		return true
	}
	if r == nil {
		return false
	}
	// Evaluate both candidate sources without short-circuit so timing does not
	// depend on which header matched first (same pattern as mcpserver).
	authOK := subtle.ConstantTimeCompare(
		[]byte(bearerFromAuthorization(r.Header.Get("Authorization"))),
		[]byte(want),
	)
	hdrOK := subtle.ConstantTimeCompare(
		[]byte(r.Header.Get(HeaderAdminToken)),
		[]byte(want),
	)
	return (authOK | hdrOK) == 1
}

// bearerFromAuthorization extracts the token from "Bearer <token>" (case-
// insensitive scheme). Returns empty when missing or malformed.
func bearerFromAuthorization(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) {
		return ""
	}
	if !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// authMiddleware gates /admin/v1/* when bearerToken is non-empty and attaches
// the configured Role to the request context for all requests.
// Non-API paths (SPA / static) pass through without the shared secret so
// loopback assets remain reachable; API always requires the token when set.
//
// Residual (UI-003): v1 uses Bearer / header shared secret (not cookies), so
// CSRF is N/A. Future httpOnly cookie sessions will require CSRF tokens.
func authMiddleware(bearerToken string, role Role, next http.Handler) http.Handler {
	if role == "" {
		role = RoleViewer
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r == nil {
			writeJSONError(w, http.StatusBadRequest, "invalid_argument", "bad request")
			return
		}
		if requiresAdminToken(r.URL.Path) && bearerToken != "" {
			if !TokenMatches(r, bearerToken) {
				w.Header().Set("WWW-Authenticate", `Bearer realm="jenkins-mcp-admin"`)
				writeJSONError(w, http.StatusUnauthorized, "authentication", "unauthorized")
				return
			}
		}
		ctx := WithRole(r.Context(), role)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission returns a middleware that responds 403 permission_denied
// when the request role lacks perm. Use for future write routes (UI-004+).
// Prefer testing via an internal test mux rather than shipping write surfaces.
func RequirePermission(perm Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			role := RoleFromContext(r.Context())
			if !role.Can(perm) {
				writeJSONError(w, http.StatusForbidden, "permission_denied", "permission denied")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// CheckPermission is a handler helper: returns true if role can perm; otherwise
// writes 403 JSON and returns false.
func CheckPermission(w http.ResponseWriter, r *http.Request, perm Permission) bool {
	role := RoleFromContext(r.Context())
	if role.Can(perm) {
		return true
	}
	writeJSONError(w, http.StatusForbidden, "permission_denied", "permission denied")
	return false
}

// requiresAdminToken reports whether path is under the admin API prefix.
func requiresAdminToken(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" {
		return false
	}
	// Exact /admin/v1 or /admin/v1/...
	return path == "/admin/v1" || strings.HasPrefix(path, "/admin/v1/")
}
