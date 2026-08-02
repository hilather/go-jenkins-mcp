package auth

import (
	"net/url"
	"strings"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// RejectJenkinsAsAuthorizationServer fails closed when asURL is co-hosted with
// the Jenkins controller (same host, case-insensitive).
//
// Stock Jenkins is a resource-server candidate, not an OAuth authorization
// server (ADR 0003 / ADR 0011 / JAS-001 default no-go). MCP OIDC issuers and
// AgentCore/gateway AS endpoints must point at an external IdP (e.g. Entra),
// never at the controller origin.
//
// Parameter order: jenkinsURL is the controller base; asURL is the candidate
// authorization-server / issuer / authorize / token / JWKS URL.
// Empty asURL is a no-op (callers validate required fields separately).
// Empty or unparseable jenkinsURL fails closed when asURL is non-empty.
func RejectJenkinsAsAuthorizationServer(jenkinsURL, asURL string) error {
	asURL = strings.TrimSpace(asURL)
	if asURL == "" {
		return nil
	}
	asHost, err := hostPort(asURL)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"authorization-server URL is invalid")
	}
	if asHost == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"authorization-server URL host is empty")
	}
	jenkinsURL = strings.TrimSpace(jenkinsURL)
	if jenkinsURL == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"jenkins URL is required to reject Jenkins-as-authorization-server misconfiguration")
	}
	jenHost, err := hostPort(jenkinsURL)
	if err != nil {
		return apperr.New(apperr.CodeInvalidArgument,
			"jenkins URL is invalid")
	}
	if jenHost == "" {
		return apperr.New(apperr.CodeInvalidArgument,
			"jenkins URL host is empty")
	}
	if strings.EqualFold(asHost, jenHost) {
		return apperr.New(apperr.CodeInvalidArgument,
			"authorization server must not use the Jenkins controller host (Jenkins is not an OAuth authorization server; default no-go — see ADR 0003 / docs/auth/jas-no-go.md)")
	}
	return nil
}

// hostPort returns the lowercase host[:port] from an absolute http(s) URL.
// Default ports (http/80, https/443) are stripped so scheme-equivalent
// controller URLs compare equal. Non-http(s) schemes fail.
func hostPort(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", apperr.New(apperr.CodeInvalidArgument, "URL scheme must be http or https")
	}
	if u.Host == "" {
		return "", nil
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "https" && port == "443") || (u.Scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return host + ":" + port, nil
	}
	return host, nil
}
