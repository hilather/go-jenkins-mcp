package auth

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/hilather/go-jenkins-mcp/internal/apperr"
)

// tokenBlobVersion is the keyring JSON schema version for TokenBundle.
const tokenBlobVersion = 1

// TokenBundle is OIDC credential material for a profile (OAUTH-004).
// Persist only via TokenStore / OS keyring — never profile JSON, logs, or MCP output.
type TokenBundle struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	// ExpiresAt is when AccessToken must be treated as stale (UTC recommended).
	ExpiresAt time.Time
	// IDToken is optional IdP identity token; never sent to Jenkins (OAUTH-003).
	IDToken string
}

// String returns a redacted, non-secret summary safe for tests and diagnostics.
// It never includes access, refresh, or id token bytes.
func (b TokenBundle) String() string {
	exp := ""
	if !b.ExpiresAt.IsZero() {
		exp = b.ExpiresAt.UTC().Format(time.RFC3339)
	}
	tt := strings.TrimSpace(b.TokenType)
	if tt == "" {
		tt = "unknown"
	}
	return "token_bundle type=" + tt +
		" has_access=" + boolStr(strings.TrimSpace(b.AccessToken) != "") +
		" has_refresh=" + boolStr(strings.TrimSpace(b.RefreshToken) != "") +
		" has_id_token=" + boolStr(strings.TrimSpace(b.IDToken) != "") +
		" expires_at=" + exp
}

// HasAccess reports whether an access token is present (non-empty).
func (b TokenBundle) HasAccess() bool {
	return strings.TrimSpace(b.AccessToken) != ""
}

// HasRefresh reports whether a refresh token is present (non-empty).
func (b TokenBundle) HasRefresh() bool {
	return strings.TrimSpace(b.RefreshToken) != ""
}

// Empty reports whether the bundle has no credential material.
func (b TokenBundle) Empty() bool {
	return !b.HasAccess() && !b.HasRefresh()
}

// AccessValid reports whether the access token is present and not past ExpiresAt
// (with optional skew: treat as expired when now+skew >= ExpiresAt).
// Zero ExpiresAt means "unknown expiry" — treated as not valid for reuse without refresh.
func (b TokenBundle) AccessValid(now time.Time, skew time.Duration) bool {
	if !b.HasAccess() {
		return false
	}
	if b.ExpiresAt.IsZero() {
		return false
	}
	if skew < 0 {
		skew = 0
	}
	return b.ExpiresAt.After(now.Add(skew))
}

// MarshalKeyring encodes the bundle for OS keyring storage (JSON, versioned).
// Callers must not log the result.
func (b TokenBundle) MarshalKeyring() ([]byte, error) {
	if b.Empty() {
		return nil, apperr.New(apperr.CodeInvalidArgument, "token bundle is empty")
	}
	blob := tokenBlobV1{
		V:            tokenBlobVersion,
		AccessToken:  b.AccessToken,
		RefreshToken: b.RefreshToken,
		TokenType:    b.TokenType,
		IDToken:      b.IDToken,
	}
	if !b.ExpiresAt.IsZero() {
		blob.ExpiresAt = b.ExpiresAt.UTC().Format(time.RFC3339Nano)
	}
	raw, err := json.Marshal(blob)
	if err != nil {
		return nil, apperr.Wrap(apperr.CodeInternal, "encode oidc token blob", err)
	}
	return raw, nil
}

// UnmarshalTokenBundle decodes a keyring blob. Corrupt/partial data fails closed
// without embedding secret bytes in the error message (OAUTH-007).
func UnmarshalTokenBundle(raw []byte) (TokenBundle, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return TokenBundle{}, apperr.New(apperr.CodeAuthentication, "oidc token blob is empty")
	}
	var blob tokenBlobV1
	if err := json.Unmarshal(raw, &blob); err != nil {
		return TokenBundle{}, apperr.New(apperr.CodeCorruptCache, "oidc token blob is corrupt")
	}
	if blob.V != 0 && blob.V != tokenBlobVersion {
		return TokenBundle{}, apperr.New(apperr.CodeCorruptCache, "oidc token blob version unsupported")
	}
	out := TokenBundle{
		AccessToken:  blob.AccessToken,
		RefreshToken: blob.RefreshToken,
		TokenType:    blob.TokenType,
		IDToken:      blob.IDToken,
	}
	if strings.TrimSpace(blob.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339Nano, blob.ExpiresAt)
		if err != nil {
			// Fallback RFC3339 without nanos.
			t, err = time.Parse(time.RFC3339, blob.ExpiresAt)
			if err != nil {
				return TokenBundle{}, apperr.New(apperr.CodeCorruptCache, "oidc token blob expiry is corrupt")
			}
		}
		out.ExpiresAt = t.UTC()
	}
	if out.Empty() {
		return TokenBundle{}, apperr.New(apperr.CodeCorruptCache, "oidc token blob has no credentials")
	}
	return out, nil
}

// tokenBlobV1 is the on-keyring JSON shape (secrets; never log).
type tokenBlobV1 struct {
	V            int    `json:"v"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
}

func boolStr(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
