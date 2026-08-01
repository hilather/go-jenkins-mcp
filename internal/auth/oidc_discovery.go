package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/simonfxr/go-jenkins-mcp/internal/apperr"
	"github.com/simonfxr/go-jenkins-mcp/internal/profile"
)

// MaxDiscoveryBodyBytes bounds OIDC discovery JSON responses (fail closed).
const MaxDiscoveryBodyBytes = 1 << 20 // 1 MiB

// DefaultDiscoveryTimeout is used when the injected client has no Timeout and
// the call context has no deadline.
const DefaultDiscoveryTimeout = 15 * time.Second

// DiscoveryDocument is the subset of OpenID Provider Metadata required for
// OAUTH-001 validation (authorization, token, JWKS). Full login/JWKS caching
// is residual (OAUTH-002 / OAUTH-003). OAUTH-007 uses RevocationEndpoint when present.
type DiscoveryDocument struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
	// Optional fields retained for diagnostics / logout (never secrets).
	UserinfoEndpoint   string `json:"userinfo_endpoint,omitempty"`
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`
	// ExpiresAt is set by the fetcher when Cache-Control max-age is present;
	// zero means no cache hint (durable metadata cache is residual).
	ExpiresAt time.Time `json:"-"`
}

// DiscoveryURL builds the OIDC discovery URL for an Issuer Identifier.
// Trailing slashes on the issuer are stripped before appending
// /.well-known/openid-configuration (OpenID Connect Discovery 1.0 §4).
func DiscoveryURL(issuer string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	if issuer == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "issuer is required")
	}
	issuer = strings.TrimRight(issuer, "/")
	u, err := url.Parse(issuer)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "", apperr.New(apperr.CodeInvalidArgument, "issuer is not a valid http(s) URL")
	}
	if u.User != nil {
		return "", apperr.New(apperr.CodeInvalidArgument, "issuer must not embed credentials")
	}
	return issuer + "/.well-known/openid-configuration", nil
}

// FetchDiscovery retrieves OpenID Provider Metadata via the injected HTTP client
// (use httptest in tests). It does not validate issuer match or Jenkins host
// separation — call ValidateDiscoveryDocument after fetch.
func FetchDiscovery(ctx context.Context, client *http.Client, issuer string) (*DiscoveryDocument, error) {
	if err := ctx.Err(); err != nil {
		return nil, apperr.Wrap(apperr.CodeCancelled, "discovery cancelled", err)
	}
	if client == nil {
		return nil, apperr.New(apperr.CodeInternal, "discovery HTTP client is required")
	}
	discURL, err := DiscoveryURL(issuer)
	if err != nil {
		return nil, err
	}

	// Bound wall time when neither client nor context has a deadline.
	if client.Timeout == 0 {
		if _, ok := ctx.Deadline(); !ok {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, DefaultDiscoveryTimeout)
			defer cancel()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discURL, nil)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "failed to build discovery request", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		if errors.Is(ctx.Err(), context.Canceled) {
			return nil, apperr.Wrap(apperr.CodeCancelled, "discovery cancelled", err)
		}
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return nil, apperr.Wrap(apperr.CodeTimeout, "discovery request timed out", err)
		}
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "discovery request failed", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxDiscoveryBodyBytes+1))
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "failed to read discovery body", err)
	}
	if len(body) > MaxDiscoveryBodyBytes {
		return nil, apperr.New(apperr.CodeUpstreamProtocol, "discovery response exceeds size limit")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, apperr.New(apperr.CodeUpstreamProtocol,
			fmt.Sprintf("discovery HTTP %d", resp.StatusCode))
	}

	var doc DiscoveryDocument
	if err := json.Unmarshal(body, &doc); err != nil {
		return nil, apperr.Wrap(apperr.CodeUpstreamProtocol, "discovery JSON is invalid", err)
	}
	if maxAge, ok := parseCacheMaxAge(resp.Header.Get("Cache-Control")); ok && maxAge > 0 {
		doc.ExpiresAt = time.Now().Add(maxAge)
	}
	return &doc, nil
}

// ValidateDiscoveryDocument checks issuer match, required endpoints, and that
// no AS endpoint host equals the Jenkins controller host (ADR 0003).
// expectedIssuer is the configured profile issuer; jenkinsURL is the controller base.
func ValidateDiscoveryDocument(doc *DiscoveryDocument, expectedIssuer, jenkinsURL string) error {
	if doc == nil {
		return apperr.New(apperr.CodeInvalidArgument, "discovery document is nil")
	}
	expectedIssuer = strings.TrimRight(strings.TrimSpace(expectedIssuer), "/")
	if expectedIssuer == "" {
		return apperr.New(apperr.CodeInvalidArgument, "expected issuer is required")
	}
	gotIssuer := strings.TrimRight(strings.TrimSpace(doc.Issuer), "/")
	if gotIssuer == "" {
		return apperr.New(apperr.CodeInvalidArgument, "discovery issuer is empty")
	}
	if gotIssuer != expectedIssuer {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("discovery issuer %q does not match configured issuer %q", gotIssuer, expectedIssuer))
	}

	// Required endpoints (OIDC Discovery + OAUTH-001); reject Jenkins co-hosting (ADR 0003).
	type ep struct {
		name string
		raw  string
	}
	authz := strings.TrimSpace(doc.AuthorizationEndpoint)
	token := strings.TrimSpace(doc.TokenEndpoint)
	jwks := strings.TrimSpace(doc.JWKSURI)
	for _, e := range []ep{
		{"authorization_endpoint", authz},
		{"token_endpoint", token},
		{"jwks_uri", jwks},
	} {
		if e.raw == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("discovery missing required %s", e.name))
		}
		u, err := url.Parse(e.raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("discovery %s is not a valid http(s) URL", e.name))
		}
		if u.Host == "" {
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("discovery %s host is empty", e.name))
		}
		if err := RejectJenkinsAsAuthorizationServer(jenkinsURL, e.raw); err != nil {
			// Preserve host-equality wording for operators; other URL errors already caught above.
			return apperr.New(apperr.CodeInvalidArgument,
				fmt.Sprintf("discovery %s must not use the Jenkins controller host (Jenkins is not the OAuth AS)", e.name))
		}
	}
	doc.AuthorizationEndpoint = authz
	doc.TokenEndpoint = token
	doc.JWKSURI = jwks
	doc.Issuer = gotIssuer

	// Issuer itself must also not be Jenkins (JAS-001 / ADR 0003).
	if err := RejectJenkinsAsAuthorizationServer(jenkinsURL, gotIssuer); err != nil {
		return err
	}
	return nil
}

// FetchAndValidateDiscovery fetches and validates discovery in one step.
func FetchAndValidateDiscovery(ctx context.Context, client *http.Client, expectedIssuer, jenkinsURL string) (*DiscoveryDocument, error) {
	doc, err := FetchDiscovery(ctx, client, expectedIssuer)
	if err != nil {
		return nil, err
	}
	if err := ValidateDiscoveryDocument(doc, expectedIssuer, jenkinsURL); err != nil {
		return nil, err
	}
	return doc, nil
}

// ValidateOIDCProfileOffline runs structural profile validation for oidc_bearer
// (no network). Convenience for CLI --offline.
func ValidateOIDCProfileOffline(p *profile.Profile) error {
	if p == nil {
		return apperr.New(apperr.CodeInvalidArgument, "profile is nil")
	}
	if p.AuthMethod != profile.AuthMethodOIDC {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("profile authMethod is %q; oauth validate-profile requires oidc_bearer", p.AuthMethod))
	}
	return p.Validate()
}

// ValidateOIDCProfileOnline runs structural validation then live discovery.
func ValidateOIDCProfileOnline(ctx context.Context, client *http.Client, p *profile.Profile) (*DiscoveryDocument, error) {
	if err := ValidateOIDCProfileOffline(p); err != nil {
		return nil, err
	}
	return FetchAndValidateDiscovery(ctx, client, p.OIDC.Issuer, p.JenkinsURL)
}

func parseCacheMaxAge(cc string) (time.Duration, bool) {
	// Minimal Cache-Control max-age parser (metadata cache residual uses this hint).
	for _, part := range strings.Split(cc, ",") {
		part = strings.TrimSpace(strings.ToLower(part))
		if strings.HasPrefix(part, "max-age=") {
			var sec int
			if _, err := fmt.Sscanf(part, "max-age=%d", &sec); err == nil && sec > 0 {
				return time.Duration(sec) * time.Second, true
			}
		}
	}
	return 0, false
}
