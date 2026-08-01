package mcpserver

import (
	"context"
	"net/http"
	"strings"
)

// HOST-001 foundation: request identity on Streamable HTTP.
//
// Shared-secret (HTTPConfig.BearerToken) is a transport gate only — not multi-user
// identity. Gateway / require-subject mode requires a per-request subject from a
// trusted source. Tool arguments must never supply identity (GWY-002).
//
// Trusted sources (foundation):
//   - Lab-only header X-Jenkins-MCP-Lab-Subject when LabIdentity is true
//     (JENKINS_MCP_LAB_IDENTITY=1). Fail closed when lab mode is off.
//   - Optional IdentityResolver (e.g. JWT validation against JWKS) injected by
//     the process; production JWT/OIDC residual until HOST-001 full pin.
//
// Never log or echo raw tokens. RequestIdentity holds only non-secret labels.

// EnvLabIdentity enables the lab-only identity header path (docker / offline tests).
// Production must not set this; residual: JWT validation only (HOST-001 / HOST-014).
const EnvLabIdentity = "JENKINS_MCP_LAB_IDENTITY"

// HeaderLabSubject is the lab-only trusted subject header. Accepted solely when
// HTTPConfig.LabIdentity is true. Never treat as production auth.
const HeaderLabSubject = "X-Jenkins-MCP-Lab-Subject"

// HeaderLabTenant is an optional lab tenant claim (lab mode only).
const HeaderLabTenant = "X-Jenkins-MCP-Lab-Tenant"

// HeaderLabWorkload is an optional lab workload claim (lab mode only).
const HeaderLabWorkload = "X-Jenkins-MCP-Lab-Workload"

// HeaderLabJenkinsPrincipal is an optional lab Jenkins principal (lab mode only).
const HeaderLabJenkinsPrincipal = "X-Jenkins-MCP-Lab-Jenkins-Principal"

// Health path constants (secret-free; may skip subject auth when RequireSubject).
const (
	HealthzPath = "/healthz"
	ReadyzPath  = "/readyz"
)

// IdentitySource labels how RequestIdentity was established (non-secret).
type IdentitySource string

const (
	// IdentitySourceNone means no trusted subject was established.
	IdentitySourceNone IdentitySource = ""
	// IdentitySourceLabHeader is the lab-only X-Jenkins-MCP-Lab-Subject path.
	IdentitySourceLabHeader IdentitySource = "lab_header"
	// IdentitySourceJWT is a validated access-token subject (resolver / production residual).
	IdentitySourceJWT IdentitySource = "jwt"
	// IdentitySourceResolver is a custom IdentityResolver result (tests / adapters).
	IdentitySourceResolver IdentitySource = "resolver"
)

// RequestIdentity is non-secret request-scoped identity material for gateway mode.
// Raw access tokens and shared secrets are never stored here.
type RequestIdentity struct {
	// ExternalSubject is the Entra/OIDC sub or lab subject label (required when set).
	ExternalSubject string
	// Tenant is optional IdP tenant id.
	Tenant string
	// WorkloadID is optional gateway workload id.
	WorkloadID string
	// JenkinsPrincipal is optional exchanged / lab Jenkins user id.
	JenkinsPrincipal string
	// Source describes the trusted origin of this identity.
	Source IdentitySource
	// Verified is true only when the trust path authenticated the caller
	// (lab mode is operator-provisioned; JWT after signature validation).
	Verified bool
}

// Present reports whether a non-empty external subject is available.
func (id RequestIdentity) Present() bool {
	return strings.TrimSpace(id.ExternalSubject) != ""
}

// IdentityResolver optionally maps an HTTP request to RequestIdentity after the
// shared-secret transport gate. Must never return raw tokens in RequestIdentity
// or error strings. Return (zero, nil) when no identity is present; return a
// non-nil error when credentials are present but invalid (fail closed → 401).
type IdentityResolver func(r *http.Request) (RequestIdentity, error)

type identityContextKey struct{}

// ContextWithIdentity returns a child context carrying id (HOST-001).
func ContextWithIdentity(ctx context.Context, id RequestIdentity) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, identityContextKey{}, id)
}

// IdentityFromContext returns RequestIdentity previously stored by the HTTP
// protect layer. Present() is false when unset.
func IdentityFromContext(ctx context.Context) RequestIdentity {
	if ctx == nil {
		return RequestIdentity{}
	}
	id, _ := ctx.Value(identityContextKey{}).(RequestIdentity)
	return id
}

// isHealthPath reports whether path is a secret-free health/ready endpoint.
func isHealthPath(path string) bool {
	p := strings.TrimSpace(path)
	if p == "" {
		return false
	}
	// Exact match only (no prefix open to MCP tool inventory leakage).
	switch p {
	case HealthzPath, ReadyzPath:
		return true
	default:
		return false
	}
}

// extractLabIdentity reads lab headers when labIdentity is enabled.
// When lab mode is off, lab headers are ignored (fail closed — no spoof).
func extractLabIdentity(r *http.Request, labIdentity bool) RequestIdentity {
	if !labIdentity || r == nil {
		return RequestIdentity{}
	}
	sub := strings.TrimSpace(r.Header.Get(HeaderLabSubject))
	if sub == "" {
		return RequestIdentity{}
	}
	// Bound subject length (fail closed on absurd values; never log).
	if len(sub) > 512 {
		return RequestIdentity{}
	}
	return RequestIdentity{
		ExternalSubject:  sub,
		Tenant:           boundClaim(r.Header.Get(HeaderLabTenant), 256),
		WorkloadID:       boundClaim(r.Header.Get(HeaderLabWorkload), 256),
		JenkinsPrincipal: boundClaim(r.Header.Get(HeaderLabJenkinsPrincipal), 256),
		Source:           IdentitySourceLabHeader,
		Verified:         true, // operator-provisioned lab trust
	}
}

func boundClaim(v string, max int) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > max {
		return ""
	}
	return v
}

// resolveRequestIdentity applies IdentityResolver (if any) then lab headers.
// Resolver wins when it returns a Present identity or an error. Lab is fallback
// for offline docker labs when resolver is nil or returns empty.
func resolveRequestIdentity(r *http.Request, labIdentity bool, resolver IdentityResolver) (RequestIdentity, error) {
	if resolver != nil {
		id, err := resolver(r)
		if err != nil {
			return RequestIdentity{}, err
		}
		if id.Present() {
			if id.Source == IdentitySourceNone {
				id.Source = IdentitySourceResolver
			}
			return id, nil
		}
	}
	return extractLabIdentity(r, labIdentity), nil
}

// writeHealthOK responds with a minimal secret-free JSON body for /healthz
// (liveness). Never includes inventory, subjects, or secrets.
func writeHealthOK(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
}

// writeReadyz responds for /readyz (HOST-005). When check is nil, reports
// process-up only ({"status":"ok"}) — gateway Ready residual not wired.
// When check is set, includes gateway_ready bool and returns 503 when not ready.
// Never includes tool inventory, tokens, subjects, or credential material.
func writeReadyz(w http.ResponseWriter, check ReadyCheck) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if check == nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}` + "\n"))
		return
	}
	if check() {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok","gateway_ready":true}` + "\n"))
		return
	}
	w.WriteHeader(http.StatusServiceUnavailable)
	_, _ = w.Write([]byte(`{"status":"not_ready","gateway_ready":false}` + "\n"))
}

// unauthorizedIdentity writes a generic 401 without echoing tokens or subjects.
func unauthorizedIdentity(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="jenkins-mcp-subject"`)
	http.Error(w, "unauthorized", http.StatusUnauthorized)
}
