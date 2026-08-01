package auth

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// ProtectedResourceMetadata is the offline RFC 9728 subset we parse from fixtures.
// Live fetch of /.well-known/oauth-protected-resource is residual (lab/operator).
// https://www.rfc-editor.org/rfc/rfc9728.html
type ProtectedResourceMetadata struct {
	// Resource is REQUIRED: the protected resource identifier (URL).
	Resource string `json:"resource"`
	// AuthorizationServers is OPTIONAL: AS issuer identifiers.
	AuthorizationServers []string `json:"authorization_servers,omitempty"`
	// JWKSURI is OPTIONAL: resource's own JWKS (not IdP JWKS in most Jenkins RS designs).
	JWKSURI string `json:"jwks_uri,omitempty"`
	// BearerMethodsSupported is OPTIONAL (e.g. "header").
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	// ScopesSupported is RECOMMENDED.
	ScopesSupported []string `json:"scopes_supported,omitempty"`
	// ResourceName is OPTIONAL human-readable name.
	ResourceName string `json:"resource_name,omitempty"`
}

// ParseProtectedResourceMetadata unmarshals RFC 9728 JSON from a fixture or body.
// Does not perform network I/O. Empty input fails closed.
func ParseProtectedResourceMetadata(data []byte) (*ProtectedResourceMetadata, error) {
	if len(data) == 0 || strings.TrimSpace(string(data)) == "" {
		return nil, fmt.Errorf("protected resource metadata JSON is empty")
	}
	var m ProtectedResourceMetadata
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("protected resource metadata JSON is invalid: %w", err)
	}
	return &m, nil
}

// ValidateProtectedResourceMetadata checks required fields when a document is present.
// resource must be a non-empty absolute http(s) URL. Optional AS issuers, when
// present, must be absolute http(s) URLs. Does not claim Jenkins publishes PRM.
//
// Edge contracts (Wave 33): reject relative URLs, non-http(s) schemes, embedded
// credentials, and empty authorization_servers entries. Scopes/bearer methods
// are informational only (not required offline).
func ValidateProtectedResourceMetadata(m *ProtectedResourceMetadata) error {
	if m == nil {
		return fmt.Errorf("protected resource metadata is nil")
	}
	res := strings.TrimSpace(m.Resource)
	if res == "" {
		return fmt.Errorf("resource is required (RFC 9728)")
	}
	if err := absoluteHTTPSOrHTTP(res, "resource"); err != nil {
		return err
	}
	for i, as := range m.AuthorizationServers {
		as = strings.TrimSpace(as)
		if as == "" {
			return fmt.Errorf("authorization_servers[%d] is empty", i)
		}
		if err := absoluteHTTPSOrHTTP(as, "authorization_servers"); err != nil {
			return err
		}
	}
	if u := strings.TrimSpace(m.JWKSURI); u != "" {
		if err := absoluteHTTPSOrHTTP(u, "jwks_uri"); err != nil {
			return err
		}
	}
	// Optional: reject empty-string entries in bearer_methods / scopes when present.
	for i, mth := range m.BearerMethodsSupported {
		if strings.TrimSpace(mth) == "" {
			return fmt.Errorf("bearer_methods_supported[%d] is empty", i)
		}
	}
	for i, sc := range m.ScopesSupported {
		if strings.TrimSpace(sc) == "" {
			return fmt.Errorf("scopes_supported[%d] is empty", i)
		}
	}
	return nil
}

func absoluteHTTPSOrHTTP(raw, field string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return fmt.Errorf("%s must be an absolute URL", field)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("%s scheme must be http or https", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not embed credentials", field)
	}
	return nil
}
