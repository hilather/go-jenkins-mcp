// Jenkins request classification for multi-layer RBAC/RO (POL-004).
// Package jenkins must not import MCP packages (FND-004); policy adapters
// implement MutationGuard using this classifier.
package jenkins

import (
	"context"
	"strings"
)

// RequestClass classifies a Jenkins HTTP call by side effect (POL-004).
type RequestClass string

const (
	// RequestRead is a safe observation (GET/HEAD/OPTIONS).
	RequestRead RequestClass = "read"
	// RequestMutate changes Jenkins state (build trigger, stop, cancel, etc.).
	RequestMutate RequestClass = "mutate"
	// RequestAuth is credential/CSRF traffic; not blocked by global read-only.
	RequestAuth RequestClass = "auth"
	// RequestUnclassified is a non-read path that is not yet allowlisted.
	// Fail closed: treat like mutate for read-only / mutation guards.
	RequestUnclassified RequestClass = "unclassified"
)

// MutationGuard optionally blocks classified Jenkins requests before network I/O
// (POL-004 network enforcement point). Nil on Client means no extra guard;
// registry and handler middleware still enforce RO/RBAC.
//
// Implementations must be safe for concurrent use and must not log secrets.
type MutationGuard interface {
	// CheckRequest is invoked with the classified request before Do.
	// Return a non-nil error to deny the call (prefer policy_denial-coded errors).
	CheckRequest(ctx context.Context, class RequestClass, method, path string) error
}

// RequiresMutationPermission reports whether class must be allowed by the
// mutation/RO gate. Auth and read never require it; mutate and unclassified do.
func RequiresMutationPermission(class RequestClass) bool {
	switch class {
	case RequestRead, RequestAuth:
		return false
	default:
		// Mutate, Unclassified, or any future unknown class → fail closed.
		return true
	}
}

// ClassifyJenkinsRequest marks method+path for POL-004 enforcement.
//
// Rules:
//   - crumbIssuer → auth (allowed under global read-only)
//   - GET/HEAD/OPTIONS → read
//   - POST/PUT/PATCH/DELETE to known mutation paths → mutate
//   - other non-idempotent methods → unclassified (fail closed under RO)
func ClassifyJenkinsRequest(method, path string) RequestClass {
	m := strings.ToUpper(strings.TrimSpace(method))
	p := normalizeRequestPath(path)

	if isAuthPath(p) {
		return RequestAuth
	}

	switch m {
	case "GET", "HEAD", "OPTIONS":
		return RequestRead
	case "POST", "PUT", "PATCH", "DELETE":
		if isKnownMutationPath(p) {
			return RequestMutate
		}
		// Fail closed: mutation-looking / unclassified write paths.
		return RequestUnclassified
	default:
		if m == "" {
			return RequestUnclassified
		}
		return RequestUnclassified
	}
}

func normalizeRequestPath(path string) string {
	p := strings.TrimSpace(path)
	if i := strings.Index(p, "?"); i >= 0 {
		p = p[:i]
	}
	if i := strings.Index(p, "#"); i >= 0 {
		p = p[:i]
	}
	// Absolute URLs: keep path component only for classification.
	if strings.Contains(p, "://") {
		if j := strings.Index(p, "://"); j >= 0 {
			rest := p[j+3:]
			if k := strings.Index(rest, "/"); k >= 0 {
				p = rest[k:]
			} else {
				p = "/"
			}
		}
	}
	if p == "" {
		return "/"
	}
	// Collapse // and lowercase for suffix checks.
	return strings.ToLower(p)
}

func isAuthPath(p string) bool {
	// Jenkins CSRF crumb issuer lives only at the server root
	// (/crumbIssuer/api/json). Segment-precise match: a job or folder named
	// "crumbIssuer" (…/job/crumbissuer/build) must not classify as auth
	// traffic — auth skips the RO/mutation gate (POL-004).
	rest := strings.TrimPrefix(p, "/")
	if rest == "crumbissuer" {
		return true
	}
	return strings.HasPrefix(rest, "crumbissuer/")
}

// isKnownMutationPath matches seed and common Jenkins write endpoints.
// Path is already lowercased and query-stripped.
func isKnownMutationPath(p string) bool {
	// Exact tail segments commonly used by this client and plugins.
	// /build and /buildWithParameters (with or without trailing slash).
	if strings.HasSuffix(p, "/build") || strings.HasSuffix(p, "/build/") {
		return true
	}
	if strings.Contains(p, "/buildwithparameters") {
		return true
	}
	// Stop / kill / term a build.
	if strings.HasSuffix(p, "/stop") || strings.HasSuffix(p, "/stop/") {
		return true
	}
	if strings.HasSuffix(p, "/kill") || strings.HasSuffix(p, "/kill/") {
		return true
	}
	if strings.HasSuffix(p, "/term") || strings.HasSuffix(p, "/term/") {
		return true
	}
	// Queue cancel.
	if strings.Contains(p, "/cancelitem") {
		return true
	}
	if strings.HasSuffix(p, "/cancel") || strings.HasSuffix(p, "/cancel/") {
		return true
	}
	// Destructive admin-ish paths (fail closed if ever reached under RO).
	if strings.HasSuffix(p, "/dodelete") || strings.HasSuffix(p, "/dodelete/") {
		return true
	}
	// Job enable/disable (power-user, not config.xml).
	if strings.HasSuffix(p, "/enable") || strings.HasSuffix(p, "/enable/") {
		return true
	}
	if strings.HasSuffix(p, "/disable") || strings.HasSuffix(p, "/disable/") {
		return true
	}
	// Build keep-forever / description.
	if strings.Contains(p, "/togglelogkeepforever") {
		return true
	}
	if strings.Contains(p, "/submitdescription") {
		return true
	}
	// Rebuild plugin / rebuild endpoint.
	if strings.Contains(p, "/rebuild") {
		return true
	}
	// Pipeline replay.
	if strings.Contains(p, "/replay") {
		return true
	}
	// NOTE: scriptText, config.xml POST, pluginManager write intentionally NOT listed
	// so they remain RequestUnclassified (fail closed under RO / mutation guard).
	return false
}
