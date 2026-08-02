package gateway

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
	"github.com/hilather/go-jenkins-mcp/internal/auth"
)

// AgentCoreConfig is non-secret configuration for an AgentCore / managed-gateway
// credential provider (GWY-001). Client secrets must never be stored here —
// only client_id and endpoint locations; secret material is keyring/vault later.
//
// Authorization server endpoints MUST point at Entra (or another approved AS),
// never at stock Jenkins (ADR 0003 / AUTH-000).
type AgentCoreConfig struct {
	// AuthorizationServerBaseURL is the AS origin (e.g. https://login.microsoftonline.com/{tenant}/v2.0).
	// Required. Must not share origin with JenkinsBaseURL.
	AuthorizationServerBaseURL string

	// AuthorizationEndpoint is optional full URL or path under the AS base.
	// When empty, discovery is expected later; still validated when set.
	AuthorizationEndpoint string

	// TokenEndpoint is optional full URL or path under the AS base.
	// When empty, discovery is expected later; still validated when set.
	TokenEndpoint string

	// Audience is the exact Jenkins API resource identifier requested in tokens.
	// Required. Never a Graph / generic gateway audience.
	Audience string

	// ClientID is the public OAuth client id (not a secret).
	ClientID string

	// Mode selects authorization_code vs token_exchange/OBO (default authorization_code).
	Mode Mode

	// JenkinsBaseURL is the Jenkins controller origin used only to reject
	// misconfiguration that points AS endpoints at Jenkins. Not an AS endpoint.
	JenkinsBaseURL string
}

// ValidateProviderConfig rejects unsafe or incomplete AgentCore configuration.
//
// Fail-closed rules:
//   - audience required
//   - authorization server base URL required and parseable (http/https)
//   - AS origin must not equal Jenkins origin
//   - authorization/token endpoints must not equal or resolve under Jenkins origin
//   - mode must be known when set
func ValidateProviderConfig(cfg AgentCoreConfig) error {
	aud := strings.TrimSpace(cfg.Audience)
	if aud == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway provider audience is required (Jenkins API resource)")
	}

	asBase := strings.TrimSpace(cfg.AuthorizationServerBaseURL)
	if asBase == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway authorization server base URL is required (must not be Jenkins)")
	}
	if _, err := normalizeOrigin(asBase); err != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"gateway authorization server base URL is invalid")
	}

	jenkinsURL := strings.TrimSpace(cfg.JenkinsBaseURL)
	// JAS-001 / ADR 0003: AS base must never be co-hosted with Jenkins.
	if jenkinsURL != "" {
		if _, err := normalizeOrigin(jenkinsURL); err != nil {
			return apperr.New(apperr.CodeInvalidArgument,
				"gateway jenkins base URL is invalid")
		}
		if err := auth.RejectJenkinsAsAuthorizationServer(jenkinsURL, asBase); err != nil {
			return err
		}
	}

	if m := strings.TrimSpace(string(cfg.Mode)); m != "" && !cfg.Mode.Valid() {
		return apperr.New(apperr.CodeInvalidArgument,
			fmt.Sprintf("unsupported gateway credential mode %q", m))
	}

	// Reject auth/token endpoints that point at Jenkins (absolute URLs only;
	// relative paths resolve under the AS base already checked above).
	for _, ep := range []struct {
		name string
		raw  string
	}{
		{"authorization endpoint", cfg.AuthorizationEndpoint},
		{"token endpoint", cfg.TokenEndpoint},
	} {
		raw := strings.TrimSpace(ep.raw)
		if raw == "" {
			continue
		}
		if err := rejectJenkinsEndpoint(ep.name, raw, jenkinsURL); err != nil {
			return err
		}
	}

	return nil
}

// rejectJenkinsEndpoint fails when an absolute endpoint is co-hosted with Jenkins.
// Relative paths are resolved against the AS base and cannot target Jenkins.
func rejectJenkinsEndpoint(name, raw, jenkinsURL string) error {
	// Absolute URL
	if strings.Contains(raw, "://") {
		if _, err := normalizeOrigin(raw); err != nil {
			return apperr.New(apperr.CodeInvalidArgument, name+" is not a valid URL")
		}
		if jenkinsURL != "" {
			if err := auth.RejectJenkinsAsAuthorizationServer(jenkinsURL, raw); err != nil {
				return apperr.New(apperr.CodeInvalidArgument,
					name+" must not point at Jenkins (Jenkins is not an OAuth authorization server)")
			}
		}
		return nil
	}

	// Relative path: must start with / and is resolved under AS — never Jenkins.
	if !strings.HasPrefix(raw, "/") {
		return apperr.New(apperr.CodeInvalidArgument,
			name+" must be an absolute URL or a path starting with /")
	}
	// Relative under AS cannot equal Jenkins unless AS is Jenkins (already rejected).
	return nil
}

// normalizeOrigin returns scheme://host[:port] lowercased host for structural
// URL validation (scheme/host/userinfo). AS vs Jenkins co-host rejection uses
// auth.RejectJenkinsAsAuthorizationServer.
func normalizeOrigin(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("empty url")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("unsupported scheme")
	}
	if u.Host == "" {
		return "", fmt.Errorf("missing host")
	}
	if u.User != nil {
		return "", fmt.Errorf("userinfo not allowed")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	// Normalize default ports away for comparison.
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return u.Scheme + "://" + host + ":" + port, nil
	}
	return u.Scheme + "://" + host, nil
}

// Configured reports whether cfg has the minimum fields for a provider instance
// (does not replace ValidateProviderConfig).
func (cfg AgentCoreConfig) Configured() bool {
	return strings.TrimSpace(cfg.AuthorizationServerBaseURL) != "" &&
		strings.TrimSpace(cfg.Audience) != ""
}
