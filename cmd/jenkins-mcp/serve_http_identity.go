package main

import (
	"context"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/auth"
	"github.com/simonfxr/go-jenkins-mcp/internal/gateway"
	"github.com/simonfxr/go-jenkins-mcp/internal/mcpserver"
)

// HOST-001 production JWKS wire: Streamable HTTP subject from JWT access tokens.
// Env values are secret-free (JWKS URL + claim pins only). Never log tokens.

const (
	// EnvHTTPJWKSURL is the JWKS document URL for inbound access-token validation
	// (lab example: http://127.0.0.1:18081/jwks). Secret-free; no credentials in URL.
	EnvHTTPJWKSURL = "JENKINS_MCP_HTTP_JWKS_URL"
	// EnvHTTPJWTIssuer is the exact expected OIDC issuer (iss claim).
	EnvHTTPJWTIssuer = "JENKINS_MCP_HTTP_JWT_ISSUER"
	// EnvHTTPJWTAudience is the exact Jenkins API resource/audience (aud claim).
	EnvHTTPJWTAudience = "JENKINS_MCP_HTTP_JWT_AUDIENCE"
	// EnvHTTPJWTRequired, when truthy with full JWKS config, forces RequireSubject
	// (non-health requests need a verified JWT subject; transport secret alone fails).
	EnvHTTPJWTRequired = "JENKINS_MCP_HTTP_JWT_REQUIRED"
	// EnvHTTPJWKSRefreshTTL is the JWKS refresh interval (Go duration). Empty/zero →
	// auth.DefaultJWKSRefreshTTL (5m); min 30s max 1h (fail closed via ParseJWKSRefreshTTL).
	// Alias of auth.EnvHTTPJWKSRefreshTTL for cmd package discoverability.
	EnvHTTPJWKSRefreshTTL = auth.EnvHTTPJWKSRefreshTTL
	// EnvHTTPJWKSMaxStale is max age of last good JWKS after a failed refresh.
	// Empty/zero → unlimited stale-if-error (default residual). When set: min 1m,
	// max 24h (fail closed via ParseJWKSMaxStaleAge). Snapshot age (memory or file).
	// Alias of auth.EnvHTTPJWKSMaxStale for cmd package discoverability.
	EnvHTTPJWKSMaxStale = auth.EnvHTTPJWKSMaxStale
	// EnvHTTPJWKSCachePath is the optional same-host multi-process JWKS snapshot
	// file (public keys only). Empty → memory-only. HOST-001/HOST-008 lite.
	// Alias of auth.EnvHTTPJWKSCachePath.
	EnvHTTPJWKSCachePath = auth.EnvHTTPJWKSCachePath
)

// resolveHTTPRequireSubject combines --http-require-subject, --gateway (caller
// passes useGateway), and JENKINS_MCP_HTTP_REQUIRE_SUBJECT (1/true/yes/on).
// AllowNonLocal always requires subject inside mcpserver.HTTPSubjectRequired.
//
// HOST-001: gateway HTTP cannot be anonymous multi-user. Loopback pilot without
// gateway may leave RequireSubject off (KD-008 residual remains explicit).
// JENKINS_MCP_HTTP_JWT_REQUIRED is applied by the caller via jwtEnv.Required OR.
func resolveHTTPRequireSubject(flagRequire, useGateway bool) bool {
	if flagRequire || useGateway {
		return true
	}
	return envHTTPRequireSubjectTruthy()
}

// envHTTPRequireSubjectTruthy reports truthy JENKINS_MCP_HTTP_REQUIRE_SUBJECT.
func envHTTPRequireSubjectTruthy() bool {
	return envHTTPBoolTruthy("JENKINS_MCP_HTTP_REQUIRE_SUBJECT")
}

// labIdentityEnabled reports JENKINS_MCP_LAB_IDENTITY (gateway + mcpserver same env).
func labIdentityEnabled() bool {
	return gateway.LabIdentityEnabled(os.Getenv)
}

// httpJWTEnv is secret-free JWKS/claim configuration for HTTP JWT subject validation.
type httpJWTEnv struct {
	JWKSURL  string
	Issuer   string
	Audience string
	// Required implies RequireSubject when Configured (EnvHTTPJWTRequired).
	Required bool
}

// Configured reports whether JWKS URL + issuer + audience are all set.
func (c httpJWTEnv) Configured() bool {
	return strings.TrimSpace(c.JWKSURL) != "" &&
		strings.TrimSpace(c.Issuer) != "" &&
		strings.TrimSpace(c.Audience) != ""
}

// parseHTTPJWTEnv loads JENKINS_MCP_HTTP_JWKS_URL / JWT_ISSUER / JWT_AUDIENCE /
// JWT_REQUIRED. Partial configuration fails closed. Values are secret-free only
// (no credentials in JWKS URL). getenv nil uses os.Getenv.
func parseHTTPJWTEnv(getenv func(string) string) (httpJWTEnv, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	urlRaw := strings.TrimSpace(getenv(EnvHTTPJWKSURL))
	iss := strings.TrimSpace(getenv(EnvHTTPJWTIssuer))
	aud := strings.TrimSpace(getenv(EnvHTTPJWTAudience))
	required := envHTTPBoolTruthyFrom(getenv(EnvHTTPJWTRequired))

	n := 0
	if urlRaw != "" {
		n++
	}
	if iss != "" {
		n++
	}
	if aud != "" {
		n++
	}
	if n == 0 {
		if required {
			return httpJWTEnv{}, apperr.New(apperr.CodeInvalidArgument,
				"JENKINS_MCP_HTTP_JWT_REQUIRED requires JENKINS_MCP_HTTP_JWKS_URL, JENKINS_MCP_HTTP_JWT_ISSUER, and JENKINS_MCP_HTTP_JWT_AUDIENCE")
		}
		return httpJWTEnv{}, nil
	}
	if n != 3 {
		return httpJWTEnv{}, apperr.New(apperr.CodeInvalidArgument,
			"HTTP JWT config requires JENKINS_MCP_HTTP_JWKS_URL, JENKINS_MCP_HTTP_JWT_ISSUER, and JENKINS_MCP_HTTP_JWT_AUDIENCE together (partial config rejected)")
	}
	if err := validateHTTPJWKSURL(urlRaw); err != nil {
		return httpJWTEnv{}, err
	}
	return httpJWTEnv{
		JWKSURL:  urlRaw,
		Issuer:   iss,
		Audience: aud,
		Required: required,
	}, nil
}

func envHTTPBoolTruthyFrom(v string) bool {
	v = strings.TrimSpace(v)
	return v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes") || strings.EqualFold(v, "on")
}

// validateHTTPJWKSURL enforces http(s) URL without embedded credentials (secret-free).
func validateHTTPJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"JENKINS_MCP_HTTP_JWKS_URL is not a valid http(s) URL")
	}
	if u.User != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"JENKINS_MCP_HTTP_JWKS_URL must not embed credentials")
	}
	return nil
}

// envHTTPJWTConfigured reports whether any HTTP JWT env is set (for --http gate).
func envHTTPJWTConfigured() bool {
	return strings.TrimSpace(os.Getenv(EnvHTTPJWKSURL)) != "" ||
		strings.TrimSpace(os.Getenv(EnvHTTPJWTIssuer)) != "" ||
		strings.TrimSpace(os.Getenv(EnvHTTPJWTAudience)) != "" ||
		envHTTPBoolTruthy(EnvHTTPJWTRequired)
}

// parseHTTPJWKSRefreshTTL loads EnvHTTPJWKSRefreshTTL via auth.ParseJWKSRefreshTTL.
// getenv nil uses os.Getenv. Empty → DefaultJWKSRefreshTTL.
func parseHTTPJWKSRefreshTTL(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	return auth.ParseJWKSRefreshTTL(getenv(EnvHTTPJWKSRefreshTTL))
}

// parseHTTPJWKSMaxStale loads EnvHTTPJWKSMaxStale via auth.ParseJWKSMaxStaleAge.
// getenv nil uses os.Getenv. Empty/zero → 0 (unlimited stale-if-error residual).
// Invalid / out-of-bounds values fail closed at serve start.
func parseHTTPJWKSMaxStale(getenv func(string) string) (time.Duration, error) {
	if getenv == nil {
		getenv = os.Getenv
	}
	return auth.ParseJWKSMaxStaleAge(getenv(EnvHTTPJWKSMaxStale))
}

// formatJWKSMaxStaleLog is a secret-free log helper (duration or "unlimited").
func formatJWKSMaxStaleLog(d time.Duration) string {
	if d <= 0 {
		return "unlimited"
	}
	return d.String()
}

// newHTTPJWKSSource builds a refreshable JWKS source for HTTP JWT subject validation.
// Initial fetch is fail-closed (unless optional same-host file snapshot is fresh
// enough). Refresh on TTL (default 5m) with stale-if-error.
// client nil → DefaultClient with DefaultJWKSTimeout. refreshTTL 0 → default.
// maxStaleAge 0 → unlimited stale-if-error; non-zero fails closed after last good
// snapshot age exceeds the bound. cachePath empty → memory-only; when set, public
// keys only under flock + 0600 (HOST-001/HOST-008 lite). Unconfigured jwtEnv →
// nil source (no error). Invalid cachePath fails closed.
//
// Residual (HOST-001 honesty): multi-pod external JWKS HA and live Entra JWKS
// under load are not claimed. Optional file is same-host multi-process lite only.
// Mid-session *subject* rebind remains mcpserver fingerprint (separate).
func newHTTPJWKSSource(
	ctx context.Context,
	client *http.Client,
	cfg httpJWTEnv,
	refreshTTL time.Duration,
	maxStaleAge time.Duration,
	cachePath string,
) (*auth.RefreshingJWKS, error) {
	if !cfg.Configured() {
		return nil, nil
	}
	if client == nil {
		client = &http.Client{Timeout: auth.DefaultJWKSTimeout}
	}
	if refreshTTL <= 0 {
		refreshTTL = auth.DefaultJWKSRefreshTTL
	}
	src, err := auth.NewRefreshingJWKS(ctx, auth.RefreshingJWKSConfig{
		Client:      client,
		URI:         cfg.JWKSURL,
		TTL:         refreshTTL,
		MaxStaleAge: maxStaleAge,
		CachePath:   cachePath,
		// Logf nil → log.Printf inside auth (non-secret refresh errors only).
	})
	if err != nil {
		return nil, err
	}
	// Optional background refresh so kids rotate even without traffic.
	// Stopped when serveCtx is cancelled (StartBackground respects parent).
	src.StartBackground(ctx)
	return src, nil
}

// fetchHTTPJWKS loads JWKS once (legacy helper for tests). Prefer newHTTPJWKSSource
// for serve wiring. Initial fetch fail-closed; no continuous refresh.
func fetchHTTPJWKS(ctx context.Context, client *http.Client, cfg httpJWTEnv) (*auth.JWKS, error) {
	if !cfg.Configured() {
		return nil, nil
	}
	if client == nil {
		client = &http.Client{Timeout: auth.DefaultJWKSTimeout}
	}
	jwks, err := auth.FetchJWKS(ctx, client, cfg.JWKSURL)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol,
			"HTTP JWT JWKS fetch failed (fail closed)", err)
	}
	return jwks, nil
}

// newHTTPIdentityResolver returns an mcpserver.IdentityResolver that:
//  1. Validates Authorization Bearer access tokens via gateway.ResolveHTTPInbound
//     (BearerAccessToken splits transport secret ≠ identity; auth.ValidateAccessToken)
//  2. Maps sub (+ tenant when present) to RequestIdentity SourceJWT Verified=true
//  3. Falls back to lab headers only when labEnabled (JENKINS_MCP_LAB_IDENTITY)
//
// jwksSource is consulted on every validation (Get) so rotated JWKS kids work
// after refresh (HOST-001 continuous JWKS foundation). StaticJWKS is fine for tests.
//
// When neither JWKS source nor lab is enabled, returns nil (protectHandler ignores
// identity headers; transport secret alone is never a subject).
//
// Fail closed: invalid JWT / JWKS Get error → error (→ 401). Never logs tokens.
// Mid-session subject rebind is enforced in mcpserver.protectHandler via
// Mcp-Session-Id + IdentityFingerprint (HOST-001).
func newHTTPIdentityResolver(
	labEnabled bool,
	sharedSecret string,
	jwksSource auth.JWKSSource,
	tokenParams auth.AccessTokenParams,
) mcpserver.IdentityResolver {
	if jwksSource == nil && !labEnabled {
		return nil
	}
	return func(r *http.Request) (mcpserver.RequestIdentity, error) {
		var j *auth.JWKS
		if jwksSource != nil {
			ctx := context.Background()
			if r != nil && r.Context() != nil {
				ctx = r.Context()
			}
			set, err := jwksSource.Get(ctx)
			if err != nil {
				// Fail closed on JWKS source failure when JWT path is configured.
				// auth scrub: no tokens in error; RefreshingJWKS logs are non-secret.
				return mcpserver.RequestIdentity{}, err
			}
			j = set
		}
		in, err := gateway.ResolveHTTPInbound(r, sharedSecret, labEnabled, j, tokenParams)
		if err != nil {
			// auth/gateway scrub raw tokens from errors.
			return mcpserver.RequestIdentity{}, err
		}
		if !in.Present() {
			return mcpserver.RequestIdentity{}, nil
		}
		src := mcpserver.IdentitySourceResolver
		switch strings.TrimSpace(in.Source) {
		case "jwt":
			src = mcpserver.IdentitySourceJWT
		case "lab_header":
			src = mcpserver.IdentitySourceLabHeader
		}
		var groups []string
		if len(in.Groups) > 0 {
			groups = append([]string(nil), in.Groups...)
		}
		return mcpserver.RequestIdentity{
			ExternalSubject:  in.ExternalSubject,
			Tenant:           in.Tenant,
			WorkloadID:       in.WorkloadID,
			JenkinsPrincipal: in.JenkinsPrincipal,
			Groups:           groups,
			Source:           src,
			Verified:         in.Verified,
		}, nil
	}
}

// newLabHTTPIdentityResolver is retained as a thin alias for lab-only tests.
// Prefer newHTTPIdentityResolver for production serve wiring.
func newLabHTTPIdentityResolver(labEnabled bool, sharedSecret string) mcpserver.IdentityResolver {
	return newHTTPIdentityResolver(labEnabled, sharedSecret, nil, auth.AccessTokenParams{})
}
