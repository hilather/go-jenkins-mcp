package gateway

import (
	"crypto/subtle"
	"net/http"
	"os"
	"strings"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/contracts"
	"github.com/simonfxr/go-jenkins-mcp/internal/policy"
)

// HOST-001 foundation: map trusted HTTP request material to policy.Subject.
//
// Identity never comes from MCP tool arguments (see RejectIdentityToolArgs).
// Shared-secret transport gates are not multi-user identity.

// EnvLabIdentity enables lab-only HTTP subject headers (docker / offline tests).
// Production residual: JWT validation against JWKS only (HOST-001 / HOST-014).
const EnvLabIdentity = "JENKINS_MCP_LAB_IDENTITY"

// Lab-only trusted headers (accepted solely when LabIdentityEnabled).
const (
	HeaderLabSubject          = "X-Jenkins-MCP-Lab-Subject"
	HeaderLabTenant           = "X-Jenkins-MCP-Lab-Tenant"
	HeaderLabWorkload         = "X-Jenkins-MCP-Lab-Workload"
	HeaderLabJenkinsPrincipal = "X-Jenkins-MCP-Lab-Jenkins-Principal"
)

// HTTPInbound is non-secret claim material extracted from a trusted HTTP path.
// Raw tokens are never stored here.
type HTTPInbound struct {
	// ExternalSubject is the Entra/OIDC sub or lab subject (required for bind).
	ExternalSubject string
	// Tenant is optional IdP tenant.
	Tenant string
	// WorkloadID is optional gateway workload id.
	WorkloadID string
	// JenkinsPrincipal is optional exchanged / lab Jenkins user id.
	JenkinsPrincipal string
	// Source is a non-secret label: lab_header | jwt | resolver.
	Source string
	// Verified is true only for a trusted authentication path.
	Verified bool
}

// Present reports whether ExternalSubject is non-empty.
func (in HTTPInbound) Present() bool {
	return strings.TrimSpace(in.ExternalSubject) != ""
}

// LabIdentityEnabled reports whether JENKINS_MCP_LAB_IDENTITY is truthy.
// getenv nil defaults to os.Getenv.
func LabIdentityEnabled(getenv func(string) string) bool {
	if getenv == nil {
		getenv = os.Getenv
	}
	return envTruthy(getenv(EnvLabIdentity))
}

// ParseLabHTTPInbound extracts lab headers when lab mode is enabled.
// When lab mode is off, returns zero inbound (headers ignored — fail closed).
// Never reads tool arguments.
func ParseLabHTTPInbound(h http.Header, labEnabled bool) HTTPInbound {
	if !labEnabled || h == nil {
		return HTTPInbound{}
	}
	sub := strings.TrimSpace(h.Get(HeaderLabSubject))
	if sub == "" || len(sub) > 512 {
		return HTTPInbound{}
	}
	return HTTPInbound{
		ExternalSubject:  sub,
		Tenant:           boundHTTPClaim(h.Get(HeaderLabTenant), 256),
		WorkloadID:       boundHTTPClaim(h.Get(HeaderLabWorkload), 256),
		JenkinsPrincipal: boundHTTPClaim(h.Get(HeaderLabJenkinsPrincipal), 256),
		Source:           "lab_header",
		Verified:         true,
	}
}

func boundHTTPClaim(v string, max int) string {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > max {
		return ""
	}
	return v
}

// BearerAccessToken extracts Authorization: Bearer material that is not the
// shared transport secret. When the bearer equals sharedSecret, it is treated
// as transport-only (returns empty). Prefer X-Jenkins-MCP-Token for the shared
// secret when Bearer carries a user access token. Never logs the token.
func BearerAccessToken(r *http.Request, sharedSecret string) string {
	if r == nil {
		return ""
	}
	raw := bearerTokenFromAuthHeader(r.Header.Get("Authorization"))
	if raw == "" {
		return ""
	}
	if sharedSecret != "" &&
		subtle.ConstantTimeCompare([]byte(raw), []byte(sharedSecret)) == 1 {
		// Transport gate token — not identity.
		return ""
	}
	return raw
}

func bearerTokenFromAuthHeader(h string) string {
	h = strings.TrimSpace(h)
	if h == "" {
		return ""
	}
	const prefix = "bearer "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(h[len(prefix):])
}

// InboundClaimsFromHTTP maps HTTPInbound to InboundClaims for BindSubject.
// profileID is required (process profile, not from the client).
func InboundClaimsFromHTTP(in HTTPInbound, profileID contracts.ProfileID) InboundClaims {
	return InboundClaims{
		Subject:          strings.TrimSpace(in.ExternalSubject),
		Tenant:           strings.TrimSpace(in.Tenant),
		WorkloadID:       strings.TrimSpace(in.WorkloadID),
		JenkinsPrincipal: strings.TrimSpace(in.JenkinsPrincipal),
		ProfileID:        profileID,
		Verified:         in.Verified,
	}
}

// BindSubjectFromHTTP maps trusted HTTPInbound to policy.Subject (GWY-002 / HOST-001).
// Tool arguments never enter this path. opts nil uses DefaultBindOptions with
// relaxed RequireTenant/RequireWorkload for lab partial claims (still require
// subject + profile + verified).
func BindSubjectFromHTTP(in HTTPInbound, profileID contracts.ProfileID, opts *BindOptions) (policy.Subject, error) {
	if !in.Present() {
		return policy.Subject{}, apperr.New(apperr.CodeAuthentication,
			"gateway http subject is required")
	}
	claims := InboundClaimsFromHTTP(in, profileID)
	bo := DefaultBindOptions()
	if opts != nil {
		bo = *opts
	} else {
		// Lab / foundation partial: subject+profile+verified required; tenant/
		// workload may be filled later by process env or OBO residual.
		bo.RequireTenant = strings.TrimSpace(in.Tenant) != ""
		bo.RequireWorkload = strings.TrimSpace(in.WorkloadID) != ""
		bo.RequireJenkinsPrincipal = strings.TrimSpace(in.JenkinsPrincipal) != ""
		bo.RequireVerified = true
	}
	return BindSubject(claims, bo)
}

// AccessTokenParams mirrors auth.AccessTokenParams for gateway HTTP JWT resolve
// (HOST-001 foundation). Production residual: live JWKS fetch/cache.
type AccessTokenParams = auth.AccessTokenParams

// ResolveHTTPInboundFromAccessToken validates a JWT-shaped access token against
// jwks and returns HTTPInbound with Source=jwt. Opaque tokens return empty
// inbound (identity residual via whoAmI — not multi-user foundation alone).
// Errors never include the raw token (auth scrub).
func ResolveHTTPInboundFromAccessToken(raw string, jwks *auth.JWKS, p auth.AccessTokenParams) (HTTPInbound, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return HTTPInbound{}, nil
	}
	res, err := auth.ValidateAccessToken(raw, jwks, p)
	if err != nil {
		return HTTPInbound{}, err
	}
	if res.Form != auth.TokenFormJWT {
		// Opaque: no local subject claims (AUTH-004 residual).
		return HTTPInbound{}, nil
	}
	sub := strings.TrimSpace(res.Claims.Subject)
	if sub == "" {
		return HTTPInbound{}, apperr.New(apperr.CodeAuthentication,
			"jwt access token subject is required")
	}
	return HTTPInbound{
		ExternalSubject: sub,
		Tenant:          strings.TrimSpace(res.Claims.TenantID),
		Source:          "jwt",
		Verified:        true,
	}, nil
}

// ResolveHTTPInbound combines lab headers and optional JWT access-token validation.
// Order: JWT when access token present and jwks non-nil; else lab headers when
// labEnabled. Shared secret must not be passed as accessToken (use BearerAccessToken).
// Never logs tokens.
func ResolveHTTPInbound(
	r *http.Request,
	sharedSecret string,
	labEnabled bool,
	jwks *auth.JWKS,
	tokenParams auth.AccessTokenParams,
) (HTTPInbound, error) {
	if r == nil {
		return HTTPInbound{}, nil
	}
	access := BearerAccessToken(r, sharedSecret)
	if access != "" && jwks != nil && len(jwks.Keys) > 0 {
		in, err := ResolveHTTPInboundFromAccessToken(access, jwks, tokenParams)
		if err != nil {
			return HTTPInbound{}, err
		}
		if in.Present() {
			return in, nil
		}
		// Opaque or empty claims: fall through to lab when enabled.
	}
	return ParseLabHTTPInbound(r.Header, labEnabled), nil
}
