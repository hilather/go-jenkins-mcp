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
	// HeaderLabGroups is a comma-separated list of group/role ids (lab mode only).
	// Bounded later by MaxInboundGroups / MaxInboundGroupNameBytes (OAUTH-006).
	HeaderLabGroups = "X-Jenkins-MCP-Lab-Groups"
)

// MaxLabGroupsHeaderBytes is the hard cap on the raw lab groups header value
// (fail closed on absurd sizes before split/parse).
const MaxLabGroupsHeaderBytes = 16 * 1024

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
	// Groups is an optional list of IdP group/role ids (JWT claims or lab header).
	// Bound at BindSubject / PolicySubjectFromHTTPInbound — never elevates deny-only.
	Groups []string
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
// Never reads tool arguments. Lab groups header is ignored when lab is off
// (spoof-resistant).
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
		Groups:           parseLabGroupsHeader(h.Get(HeaderLabGroups)),
		Source:           "lab_header",
		Verified:         true,
	}
}

// parseLabGroupsHeader splits a comma-separated lab groups header into a
// pre-bound list (empty tokens dropped). Oversize header values yield nil
// (fail closed — do not invent membership from truncated garbage).
// Final caps (MaxInboundGroups, name length, overage) apply at BindSubject /
// PolicySubjectFromHTTPInbound.
func parseLabGroupsHeader(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if len(raw) > MaxLabGroupsHeaderBytes {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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
// Groups are copied when present (bounded at BindSubject).
func InboundClaimsFromHTTP(in HTTPInbound, profileID contracts.ProfileID) InboundClaims {
	var groups []string
	if len(in.Groups) > 0 {
		groups = append([]string(nil), in.Groups...)
	}
	return InboundClaims{
		Subject:          strings.TrimSpace(in.ExternalSubject),
		Tenant:           strings.TrimSpace(in.Tenant),
		Groups:           groups,
		WorkloadID:       strings.TrimSpace(in.WorkloadID),
		JenkinsPrincipal: strings.TrimSpace(in.JenkinsPrincipal),
		ProfileID:        profileID,
		Verified:         in.Verified,
	}
}

// InboundClaimsFromRequestIdentity maps trusted HTTPInbound to InboundClaims
// with fail-closed checks (GWY-002). Requires subject and profileID; sets
// Verified from inbound (must be true for production DefaultBindOptions).
// Tool arguments never enter this path (see RejectIdentityToolArgs).
// Groups are copied when present (bounded at BindSubject).
func InboundClaimsFromRequestIdentity(in HTTPInbound, profileID contracts.ProfileID) (InboundClaims, error) {
	sub := strings.TrimSpace(in.ExternalSubject)
	if sub == "" {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"gateway request identity subject is required")
	}
	pid := contracts.ProfileID(strings.TrimSpace(string(profileID)))
	if pid == "" {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"gateway profile id is required for request identity")
	}
	if !in.Verified {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"gateway request identity is not verified")
	}
	var groups []string
	if len(in.Groups) > 0 {
		groups = append([]string(nil), in.Groups...)
	}
	return InboundClaims{
		Subject:          sub,
		Tenant:           strings.TrimSpace(in.Tenant),
		Groups:           groups,
		WorkloadID:       strings.TrimSpace(in.WorkloadID),
		JenkinsPrincipal: strings.TrimSpace(in.JenkinsPrincipal),
		ProfileID:        pid,
		Verified:         true,
	}, nil
}

// InboundClaimsFromJWTClaims maps verified JWT access-token claims to
// InboundClaims (GWY-002 / HOST-010). Sets Verified=true.
//
// Required: claims.Subject and profileID. Tenant maps from tid; groups from
// claim groups; preferred_username → JenkinsPrincipal when present.
// workloadID is process/gateway workload (not a standard JWT claim) and may
// be empty when BindOptions.RequireWorkload is relaxed.
//
// Input must be from ValidateAccessToken (or equivalent) — never raw tool args
// and never an ID token used as Jenkins API credential.
func InboundClaimsFromJWTClaims(c auth.AccessTokenClaims, profileID contracts.ProfileID, workloadID string) (InboundClaims, error) {
	sub := strings.TrimSpace(c.Subject)
	if sub == "" {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"jwt access token subject is required")
	}
	pid := contracts.ProfileID(strings.TrimSpace(string(profileID)))
	if pid == "" {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"gateway profile id is required for jwt claim binding")
	}
	// token_use=id_token must never bind as API identity path elevation.
	use := strings.ToLower(strings.TrimSpace(c.TokenUse))
	if use == "id_token" {
		return InboundClaims{}, apperr.New(apperr.CodeAuthentication,
			"id_token claims cannot be used as gateway api identity")
	}
	var groups []string
	if len(c.Groups) > 0 {
		groups = append([]string(nil), c.Groups...)
	}
	return InboundClaims{
		Subject:          sub,
		Tenant:           strings.TrimSpace(c.TenantID),
		Groups:           groups,
		WorkloadID:       strings.TrimSpace(workloadID),
		JenkinsPrincipal: strings.TrimSpace(c.PreferredUsername),
		ProfileID:        pid,
		Verified:         true,
	}, nil
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
	var groups []string
	if len(res.Claims.Groups) > 0 {
		groups = append([]string(nil), res.Claims.Groups...)
	}
	return HTTPInbound{
		ExternalSubject:  sub,
		Tenant:           strings.TrimSpace(res.Claims.TenantID),
		JenkinsPrincipal: strings.TrimSpace(res.Claims.PreferredUsername),
		Groups:           groups,
		Source:           "jwt",
		Verified:         true,
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
